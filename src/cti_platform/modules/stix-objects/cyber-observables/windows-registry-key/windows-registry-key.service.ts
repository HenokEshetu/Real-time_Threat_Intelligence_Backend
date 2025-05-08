import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateWindowsRegistryKeyInput, UpdateWindowsRegistryKeyInput } from './windows-registry-key.input';
import { WindowsRegistryKey } from './windows-registry-key.entity';
import { SearchWindowsRegistryKeyInput } from './windows-registry-key.resolver';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@Injectable()
export class WindowsRegistryKeyService extends BaseStixService<WindowsRegistryKey> implements OnModuleInit {
  protected typeName = ' windows-registry-key';
  private readonly index = 'windows-registry-keys';
  private readonly logger = console; // Replace with a proper logger if needed


  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createWindowsRegistryKeyInput: CreateWindowsRegistryKeyInput): Promise<WindowsRegistryKey> {



    const windowsRegistryKey: WindowsRegistryKey = {
      ...createWindowsRegistryKeyInput,

      id: createWindowsRegistryKeyInput.id,
      type: 'windows-registry-key' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),

    };



    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: windowsRegistryKey.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: windowsRegistryKey.id });

      const existingDoc = await this.findOne(windowsRegistryKey.id);
      return existingDoc;

    }
    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: windowsRegistryKey.id,
        body: windowsRegistryKey,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index Windows Registry Key document');
      }

      await this.publishCreated(windowsRegistryKey)

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
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'windows-registry-key' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),

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

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedRegistryKey },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update Windows Registry Key document');
      }

      await this.publishUpdated(updatedRegistryKey)

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
      const response = await this.openSearchService.delete({ index: this.index, id });
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
                range: { [key]: { gte: value, lte: value } },
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
          type: 'windows-registry-key' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),

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