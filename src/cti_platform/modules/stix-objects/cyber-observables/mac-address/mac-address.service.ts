import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateMACAddressInput, UpdateMACAddressInput } from './mac-address.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchMACAddressInput } from './mac-address.resolver';
import { MACAddress } from './mac-address.entity';

@Injectable()
export class MACAddressService implements OnModuleInit {
  private readonly index = 'mac-addresses';
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

  async create(createMACAddressInput: CreateMACAddressInput): Promise<MACAddress> {
    const id = `mac-${uuidv4()}`;
    const now = new Date().toISOString();

    const doc: MACAddress = {
      id,
      type: 'mac-addr' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
      value: createMACAddressInput.value, // Required field
      ...createMACAddressInput,
      ...(createMACAddressInput.enrichment ? { enrichment: createMACAddressInput.enrichment } : {}),
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
      throw new StixValidationError(`Failed to create MAC address: ${error.meta?.body?.error || error.message}`);
    }
  }

  async findOne(id: string): Promise<MACAddress> {
    try {
      const response = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        id,
        type: 'mac-addr' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        value: source.value, // Ensure required field is included
        ...source,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`MAC address with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch MAC address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateMACAddressInput: UpdateMACAddressInput): Promise<MACAddress> {
    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<MACAddress> = {
        ...updateMACAddressInput,
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
      throw new StixValidationError(`Failed to update MAC address: ${error.meta?.body?.error || error.message}`);
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
        message: 'Failed to delete MAC address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    from: number = 0,
    size: number = 10,
    filter: SearchMACAddressInput = {}
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: MACAddress[];
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

      for (const [key, value] of Object.entries(filter)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'value':
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
        results: response.body.hits.hits.map((hit) => ({
          id: hit._id,
          type: 'mac-addr' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          value: hit._source.value, // Ensure required field is included
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search MAC addresses',
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
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize mac-addresses index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}