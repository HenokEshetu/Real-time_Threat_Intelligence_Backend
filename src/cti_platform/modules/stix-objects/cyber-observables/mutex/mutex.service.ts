import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client,  } from '@opensearch-project/opensearch';
import { CreateMutexInput, UpdateMutexInput } from './mutex.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchMutexInput } from './mutex.resolver';
import { Mutex } from './mutex.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class MutexService extends BaseStixService<Mutex> implements OnModuleInit {
  protected typeName = ' mac-addr';
  private readonly index = 'mutexes';
  private readonly logger = console; // Replace with a proper logger if needed
  

  constructor(
              @Inject(PUB_SUB) pubSub: RedisPubSub,
              @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
            ) {
              super(pubSub);
            }

  async onModuleInit() {
    await this.ensureIndex();}

  async create(createMutexInput: CreateMutexInput): Promise<Mutex> {
    
    const now = new Date();

    const doc: Mutex = {
      ...createMutexInput,
     
      id: createMutexInput.id ,
      type: 'mutex' as const,
      spec_version: '2.1',
      created: now.toISOString(),
      modified: now.toISOString(),
      name: createMutexInput.name, // Required field
      
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
      throw new StixValidationError(`Failed to create mutex: ${error.meta?.body?.error || error.message}`);
    }
  }

  async findOne(id: string): Promise<Mutex> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id,
        type: 'mutex' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Mutex with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch mutex',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateMutexInput: UpdateMutexInput): Promise<Mutex> {
    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<Mutex> = {
        ...updateMutexInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update document');
      }

      const updatedMutex: Mutex = {
                                  ...existing,
                                  ...updatedDoc,
                                  
                                  spec_version: existing.spec_version || '2.1',
                                };

                                await this.publishUpdated(updatedMutex);
                        return updatedMutex;
      
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new StixValidationError(`Failed to update mutex: ${error.meta?.body?.error || error.message}`);
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
        message: 'Failed to delete mutex',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByName(name: string): Promise<Mutex[]> {
    try {
      const response = await this.openSearchService.search({
        index: this.index,
        body: {
          query: {
            match: { name: { query: name, lenient: true } },
          },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
        type: 'mutex' as const,
        spec_version: hit._source.spec_version || '2.1',
        created: hit._source.created || new Date(),
        modified: hit._source.modified || new Date(),
        name: hit._source.name, // Required field
        
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: `Failed to fetch mutexes with name ${name}`,
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    from: number = 0,
    size: number = 10,
    filters: SearchMutexInput = {}
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Mutex[];
  }> {
    try {
      const queryBuilder: { query: any; sort?: any[] } = {
        query: {
          bool: {
            must: [],
            filter: [],
          },
        },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      Object.entries(filters).forEach(([key, value]) => {
        if (value === undefined || value === null) return;

        switch (key) {
          case 'name':
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
              term: { [key]: value },
            });
        }
      });

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.openSearchService.search({
        index: this.index,
        from,
        size,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;

      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results: response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          type: 'mutex' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          name: hit._source.name, // Required field
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search mutexes',
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
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                name: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize mutexes index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}