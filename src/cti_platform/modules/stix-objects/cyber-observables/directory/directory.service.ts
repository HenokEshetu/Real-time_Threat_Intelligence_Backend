import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { Directory } from './directory.entity';
import { CreateDirectoryInput, UpdateDirectoryInput } from './directory.input';
import { SearchDirectoryInput } from './directory.resolver';

@Injectable()
export class DirectoryService implements OnModuleInit{
  private readonly index = 'directories';
  private readonly openSearchClient: Client;

  constructor() {
    const clientOptions: ClientOptions = {
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
      ssl: process.env.OPENSEARCH_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      auth: process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD
        ? {
            username: process.env.OPENSEARCH_USERNAME,
            password: process.env.OPENSEARCH_PASSWORD,
          }
        : undefined,
    };
    this.openSearchClient = new Client(clientOptions);
    
  }

  async onModuleInit() {
    await this.ensureIndex();}

  async create(createDirectoryInput: CreateDirectoryInput): Promise<Directory> {
    
    const now = new Date().toISOString();

    const doc: Directory = {
      id: createDirectoryInput.id,
      type: 'directory' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
      path: createDirectoryInput.path,
      ...createDirectoryInput,
    };

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id: doc.id,
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }
      return doc;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create directory',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateDirectoryInput: UpdateDirectoryInput): Promise<Directory> {
    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<Directory> = {
        ...updateDirectoryInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update document');
      }

      return { ...existing, ...updatedDoc };
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
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;

      return {
        id,
        type: 'directory' as const,
        spec_version: '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        path: source.path,
        ...source,
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
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: { match: { path: { query: path, lenient: true } } },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'directory' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        path: hit._source.path,
        ...hit._source,
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to find directories by path',
        details: error.meta?.body?.error || error.message,
      });
    }
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
                range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
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

      const response = await this.openSearchClient.search({
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
          id: hit._id,
          type: 'directory' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          path: hit._source.path,
          ...hit._source,
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
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });
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
      const exists = await this.openSearchClient.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchClient.indices.create({
          index: this.index,
          body: {
            mappings: {
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