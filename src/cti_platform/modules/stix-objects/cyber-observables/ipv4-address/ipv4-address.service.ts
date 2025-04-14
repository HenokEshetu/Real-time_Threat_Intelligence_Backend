import { Injectable, InternalServerErrorException, NotFoundException,OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateIPv4AddressInput, UpdateIPv4AddressInput } from './ipv4-address.input';
import { IPv4Address } from './ipv4-address.entity';
import { SearchIPv4AddressInput } from './ipv4-address.resolver';

@Injectable()
export class IPv4AddressService implements OnModuleInit{
  private readonly index = 'ipv4-addresses';
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

  async create(createIPv4AddressInput: CreateIPv4AddressInput): Promise<IPv4Address> {
    const id = `ipv4-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const now = new Date().toISOString();

    const doc: IPv4Address = {
      id,
      type: 'ipv4-addr' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
      value: createIPv4AddressInput.value,
      resolves_to_refs: createIPv4AddressInput.resolves_to_refs || [],
      belongs_to_refs: createIPv4AddressInput.belongs_to_refs || [],
      ...createIPv4AddressInput,
      ...(createIPv4AddressInput.enrichment ? { enrichment: createIPv4AddressInput.enrichment } : {}),
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
      throw new InternalServerErrorException({
        message: 'Failed to create IPv4 address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateIPv4AddressInput: UpdateIPv4AddressInput): Promise<IPv4Address> {
    try {
      const existing = await this.findOne(id);
      if (!existing) {
        throw new NotFoundException(`IPv4 Address with ID ${id} not found`);
      }

      const updatedDoc: Partial<IPv4Address> = {
        ...updateIPv4AddressInput,
        resolves_to_refs: updateIPv4AddressInput.resolves_to_refs ?? existing.resolves_to_refs,
        belongs_to_refs: updateIPv4AddressInput.belongs_to_refs ?? existing.belongs_to_refs,
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
        message: 'Failed to update IPv4 address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<IPv4Address> {
    try {
      const response = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        id,
        type: 'ipv4-addr' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        value: source.value,
        resolves_to_refs: source.resolves_to_refs || [],
        belongs_to_refs: source.belongs_to_refs || [],
        ...source,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`IPv4 Address with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch IPv4 address',
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
        message: 'Failed to delete IPv4 address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByValue(value: string): Promise<IPv4Address[]> {
    try {
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: {
            match: { value: { query: value, lenient: true } },
          },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'ipv4-addr' as const,
        spec_version: hit._source.spec_version || '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        value: hit._source.value,
        resolves_to_refs: hit._source.resolves_to_refs || [],
        belongs_to_refs: hit._source.belongs_to_refs || [],
        ...hit._source,
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to find IPv4 addresses by value',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchIPv4AddressInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: IPv4Address[];
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
          case 'value':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'resolves_to_refs':
          case 'belongs_to_refs':
            if (Array.isArray(value)) {
              queryBuilder.query.bool.filter.push({
                terms: { [key]: value },
              });
            }
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
          type: 'ipv4-addr' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          value: hit._source.value,
          resolves_to_refs: hit._source.resolves_to_refs || [],
          belongs_to_refs: hit._source.belongs_to_refs || [],
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search IPv4 addresses',
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
                value: { type: 'keyword' },
                resolves_to_refs: { type: 'keyword' },
                belongs_to_refs: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize ipv4-addresses index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}