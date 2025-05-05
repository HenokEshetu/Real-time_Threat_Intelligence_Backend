import { Injectable, InternalServerErrorException, NotFoundException , OnModuleInit} from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateAutonomousSystemInput, UpdateAutonomousSystemInput } from './autonomous-system.input';
import { AutonomousSystem } from './autonomous-system.entity';
import { SearchAutonomousSystemInput } from './autonomous-system.resolver';

import { v5 as uuidv5 } from 'uuid';

  // Define the UUID namespace 
  const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

@Injectable()
export class AutonomousSystemService implements OnModuleInit {
  private readonly index = 'autonomous-systems';
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

  async searchWithFilters(
    searchParams: SearchAutonomousSystemInput = {},
    from: number = 0,
    size: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: AutonomousSystem[];
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

      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'number':
            queryBuilder.query.bool.filter.push({ term: { [key]: value } });
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
        results: response.body.hits.hits.map(hit => ({
          id: hit._id,
          number: hit._source.number,
          type: 'autonomous-system' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Error fetching Autonomous Systems',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
  
  
  async create(createAutonomousSystemInput: CreateAutonomousSystemInput): Promise<AutonomousSystem> {
    const now = new Date().toISOString();
  
    // Generate ID if not provided
    const id = createAutonomousSystemInput.id || uuidv5(JSON.stringify(createAutonomousSystemInput), NAMESPACE);
  
    const doc: AutonomousSystem = {
      ...createAutonomousSystemInput,
      id,
      type: 'autonomous-system' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
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
        message: 'Failed to create Autonomous System',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateAutonomousSystemInput: UpdateAutonomousSystemInput): Promise<AutonomousSystem> {
    try {
      const existing = await this.findOneById(id);
      const updatedDoc = {
        ...updateAutonomousSystemInput,
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
        message: 'Failed to update Autonomous System',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOneById(id: string): Promise<AutonomousSystem> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;

      return {
        ...source,
        id,
        number: source.number,
        type: 'autonomous-system' as const,
        spec_version: '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Autonomous System with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch Autonomous System',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByNumber(number: number): Promise<AutonomousSystem> {
    try {
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: { term: { number } },
        },
      });

      if (!response.body.hits.hits.length) {
        throw new NotFoundException(`Autonomous System with number ${number} not found`);
      }

      const hit = response.body.hits.hits[0];
      return {
        ...hit._source,
        id: hit._id,
        number: hit._source.number,
        type: 'autonomous-system' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        
      };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to find Autonomous System by number',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({ index: this.index, id });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false; // Return false instead of throwing for idempotency
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete Autonomous System',
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
                number: { type: 'integer' },
                name: { type: 'text' },
                rir: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize autonomous-systems index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}