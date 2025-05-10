import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { Directory } from './directory.entity';
import { CreateDirectoryInput, UpdateDirectoryInput } from './directory.input';
import { SearchDirectoryInput } from './directory.resolver';

import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { StixValidationError } from 'src/cti_platform/core/exception/custom-exceptions';

  
import { v5 as uuidv5 } from 'uuid';
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';



@Injectable()
export class DirectoryService extends BaseStixService<Directory> implements OnModuleInit {
  private readonly logger = console; // Replace with a proper logger if needed
  protected typeName = 'directory';
  private readonly index = 'directories';
 

  constructor(
            @Inject(PUB_SUB) pubSub: RedisPubSub,
            @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
          ) {
            super(pubSub);
          }


  async onModuleInit() {
    await this.ensureIndex();}

  async create(createDirectoryInput: CreateDirectoryInput): Promise<Directory> {
    
    const now = new Date();

    const doc: Directory = {
      ...createDirectoryInput,
      id: createDirectoryInput.id,
      type: 'directory' as const,
      spec_version: '2.1',
      created: now.toISOString(),
      modified: now.toDateString(),
      path: createDirectoryInput.path,
      
    };

    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: doc.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: doc.id });

      const existingDoc = await this.findOne(doc.id);
      return existingDoc;
    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: doc.id,
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }
      await this.publishCreated(doc);
      return doc;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create directory',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateDirectoryInput: UpdateDirectoryInput): Promise<Directory> {
    // Validate input if necessary
    this.validateDirectory(updateDirectoryInput);
  
    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<Directory> = {
        ...updateDirectoryInput,
        modified: new Date().toISOString(),
      };
  
      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });
  
      if (response.body.result !== 'updated') {
        throw new Error('Failed to update directory');
      }
  
      const updatedDirectory: Directory = {
        ...existing,
        ...updatedDoc,
        type: 'directory' as const, 
        spec_version: existing.spec_version || '2.1', 
      };
  
      
      await this.publishUpdated(updatedDirectory);
  
      return updatedDirectory;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update directory',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
  async findOne(id: string): Promise<Directory> {
    try {
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;

      return {
        ...source,
        id,
        type: 'directory' as const,
        spec_version: '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        path: source.path,
       
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Directory with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch directory',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByPath(path: string): Promise<Directory[]> {
    try {
      const response = await this.openSearchService.search({
        index: this.index,
        body: {
          query: { match: { path: { query: path, lenient: true } } },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
        type: 'directory' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date(),
        modified: hit._source.modified || new Date(),
        path: hit._source.path,
        
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to find directories by path',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
  private validateDirectory(input: CreateDirectoryInput | UpdateDirectoryInput): void {
    // Check if path is provided (required for creation, optional for update)
    if ('path' in input && input.path === undefined && !('id' in input)) {
      throw new StixValidationError('Directory path is required for creation');
    }
  
    // Validate path format if provided
    if (input.path !== undefined && input.path !== null) {
      if (typeof input.path !== 'string' || !this.isValidPath(input.path)) {
        throw new StixValidationError(
          'Invalid directory path. Path must be a valid file system path (e.g., /home/user/docs or C:\\Users\\Docs)'
        );
      }
    }
  
    // Additional STIX-specific validations (if applicable)
    if ('spec_version' in input && input.spec_version && input.spec_version !== '2.1') {
      throw new StixValidationError('Directory spec_version must be 2.1');
    }
  }

  private isValidPath(path: string): boolean {
    if (!path || path.trim() === '') {
      return false;
    }

    const pathRegex = /^(?:[a-zA-Z]:\\(?:[^<>:"|?*\n\r]+\\)*[^<>:"|?*\n\r]*$|\/(?:[^<>:"|?*\n\r]+\/)*[^<>:"|?*\n\r]*$|\.\/(?:[^<>:"|?*\n\r]+\/)*[^<>:"|?*\n\r]*$|\.\.\/(?:[^<>:"|?*\n\r]+\/)*[^<>:"|?*\n\r]*$)/;

    return (
      pathRegex.test(path) &&
      !/[\x00-\x1F\x7F]/.test(path) &&
      path.length <= 1024 &&
      !/[\\\/]$/.test(path)
    );
  }
  async searchWithFilters(
    searchParams: SearchDirectoryInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Directory[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const queryBuilder: { query: any; sort?: any[] } = {
        query: {
          bool: {
            must: [],
            filter: [],
          },
        },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'path':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'created':
          case 'modified':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value, lte: value } },
              });
            }
            break;
          default:
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
        }
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;

      return {
        
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results: response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          type: 'directory' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          path: hit._source.path,
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search directories',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
      });
      const success = response.body.result === 'deleted';
      if (success) {
        await this.publishDeleted(id);
      }
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete directory',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchService.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchService.indices.create({
          index: this.index,
          body: {
            mappings: {
              dynamic: 'true',
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                path: { type: 'text' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize directories index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}