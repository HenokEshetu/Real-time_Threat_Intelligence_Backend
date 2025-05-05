import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateWindowsRegistryKeyInput, UpdateWindowsRegistryKeyInput } from './windows-registry-key.input';
import { WindowsRegistryKey } from './windows-registry-key.entity';
import { SearchWindowsRegistryKeyInput } from './windows-registry-key.resolver';

@Injectable()
export class WindowsRegistryKeyService implements OnModuleInit  {
  private readonly index = 'windows-registry-keys';
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

  async create(createWindowsRegistryKeyInput: CreateWindowsRegistryKeyInput): Promise<WindowsRegistryKey> {
    const windowsRegistryKey: WindowsRegistryKey = {
      ...createWindowsRegistryKeyInput,
     
      id: `windows-registry-key--${uuidv4()}`,
      type: 'windows-registry-key' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      
    };

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id: windowsRegistryKey.id,
        body: windowsRegistryKey,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index Windows Registry Key document');
      }
      return windowsRegistryKey;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create Windows Registry Key',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<WindowsRegistryKey> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'windows-registry-key' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
       
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Windows Registry Key with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch Windows Registry Key',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateWindowsRegistryKeyInput: UpdateWindowsRegistryKeyInput): Promise<WindowsRegistryKey> {
    try {
      const existingRegistryKey = await this.findOne(id);
      const updatedRegistryKey: WindowsRegistryKey = {
        ...existingRegistryKey,
        ...updateWindowsRegistryKeyInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedRegistryKey },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update Windows Registry Key document');
      }

      return updatedRegistryKey;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update Windows Registry Key',
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
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete Windows Registry Key',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchWindowsRegistryKeyInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: WindowsRegistryKey[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'key':
          case 'creator_user_ref':
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
          case 'number_of_subkeys':
            queryBuilder.query.bool.filter.push({
              term: { [key]: value },
            });
            break;
          case 'values':
            if (Array.isArray(value)) {
              queryBuilder.query.bool.filter.push({
                terms: { [key]: value },
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
          ...hit._source,
          id: hit._id,
          type: 'windows-registry-key' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search Windows Registry Keys',
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
                key: { type: 'keyword' },
                values: { type: 'keyword' },
                number_of_subkeys: { type: 'integer' },
                creator_user_ref: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize windows-registry-keys index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}