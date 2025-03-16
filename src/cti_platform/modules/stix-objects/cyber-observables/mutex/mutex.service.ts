import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateMutexInput, UpdateMutexInput } from './mutex.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchMutexInput } from './mutex.resolver';
import { Mutex } from './mutex.entity';

@Injectable()
export class MutexService implements OnModuleInit  {
  private readonly index = 'mutexes';
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

  async create(createMutexInput: CreateMutexInput): Promise<Mutex> {
    const id = `mutex-${uuidv4()}`;
    const now = new Date().toISOString();

    const doc: Mutex = {
      id,
      type: 'mutex' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
      name: createMutexInput.name, // Required field
      ...createMutexInput,
    };

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }
      return doc;
    } catch (error) {
      throw new StixValidationError(`Failed to create mutex: ${error.meta?.body?.error || error.message}`);
    }
  }

  async findOne(id: string): Promise<Mutex> {
    try {
      const response = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        id,
        type: 'mutex' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        name: source.name, // Required field
        ...source,
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
      throw new StixValidationError(`Failed to update mutex: ${error.meta?.body?.error || error.message}`);
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
        message: 'Failed to delete mutex',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByName(name: string): Promise<Mutex[]> {
    try {
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: {
            match: { name: { query: name, lenient: true } },
          },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'mutex' as const,
        spec_version: hit._source.spec_version || '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        name: hit._source.name, // Required field
        ...hit._source,
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
                range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
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

      const response = await this.openSearchClient.search({
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
          id: hit._id,
          type: 'mutex' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          name: hit._source.name, // Required field
          ...hit._source,
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