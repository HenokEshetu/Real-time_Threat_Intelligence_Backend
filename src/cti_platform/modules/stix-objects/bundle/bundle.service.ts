import { Injectable, NotFoundException, InternalServerErrorException, OnModuleInit, Inject } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { Bundle } from './bundle.entity';
import { CreateBundleInput, UpdateBundleInput } from './bundle.input';
import { SearchBundleInput } from './bundle.resolver';
import { BaseStixService } from '../base-stix.service';
import { PUB_SUB } from '../../pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Logger } from '@nestjs/common';
import * as retry from 'async-retry';

@Injectable()
export class BundleService extends BaseStixService<Bundle> implements OnModuleInit {
  protected typeName = 'bundle';
  private readonly logger = new Logger(BundleService.name);
  private readonly index = 'bundles';

  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client,
  ) {
    super(pubSub);
  }

  async onModuleInit() {
    await this.ensureIndexExists().catch((error) => {
      this.logger.error(`Failed to ensure index exists: ${error.message}`, error);
      throw error;
    });
  }

  public getClient(): Client {
    return this.openSearchService;
  }

  async create(createBundleInput: CreateBundleInput): Promise<Bundle> {
    const bundle: Bundle = {
      ...createBundleInput,
      id: createBundleInput.id,
      type: 'bundle',
      spec_version: createBundleInput.spec_version || '2.1',
      created: createBundleInput.created || new Date().toISOString(),
      modified: createBundleInput.modified || new Date().toISOString(),
    };

    try {
      return await retry.default(
        async () => {
          const exists = await this.openSearchService.exists({
            index: this.index,
            id: bundle.id,
          });

          if (exists.body) {
            this.logger.warn(`Document already exists`, { id: bundle.id });
            return await this.findOne(bundle.id);
          }

          const response = await this.openSearchService.index({
            index: this.index,
            id: bundle.id,
            body: bundle,
            refresh: 'wait_for',
            op_type: 'create',
          });

          if (response.body.result !== 'created') {
            throw new Error(`Failed to create document: ${response.body.result}`);
          }

          await this.publishCreated(bundle);
          return bundle;
        },
        {
          retries: 5,
          factor: 2,
          minTimeout: 2000,
          maxTimeout: 10000,
          onRetry: (error) => {
            this.logger.warn(`Retrying bundle ${bundle.id}: ${error.message}`);
          },
        },
      );
    } catch (error) {
      this.logger.error(`Error creating bundle ${bundle.id}: ${error.message}`, {
        error: error.meta?.body?.error || error,
      });
      throw new InternalServerErrorException({
        message: 'Error creating bundle',
        error: error.message,
        details: error.meta?.body?.error || error,
      });
    }
  }

  async findOne(id: string): Promise<Bundle> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return {
        ...response.body._source,
        id: response.body._id,
      } as Bundle;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Bundle with ID ${id} not found`);
      }
      this.logger.error(`Error fetching bundle ${id}: ${error.message}`, {
        error: error.meta?.body?.error || error,
      });
      throw new InternalServerErrorException({
        message: 'Error fetching bundle',
        error: error.message,
        details: error.meta?.body?.error || error,
      });
    }
  }

  async searchWithFilters(
    filters: SearchBundleInput,
    page: number = 1,
    pageSize: number = 10,
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Bundle[];
  }> {
    const from = (page - 1) * pageSize;
    const queryBuilder = {
      query: {
        bool: {
          must: [] as any[],
          filter: [] as any[],
        },
      },
      sort: [{ modified: { order: 'desc' } as const }],
    };

    for (const [key, value] of Object.entries(filters)) {
      if (value === undefined || value === null) continue;

      switch (typeof value) {
        case 'string':
          queryBuilder.query.bool.must.push({
            query_string: {
              query: `${key}:${value}*`,
              default_operator: 'AND',
            },
          });
          break;
        case 'number':
        case 'boolean':
          queryBuilder.query.bool.filter.push({
            term: { [key]: value },
          });
          break;
        case 'object':
          if (value instanceof Date) {
            queryBuilder.query.bool.filter.push({
              range: { [key]: { gte: value, lte: value } },
            });
          } else if (Array.isArray(value)) {
            queryBuilder.query.bool.filter.push({
              terms: { [key]: value },
            });
          }
          break;
      }
    }

    if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
      queryBuilder.query = { match_all: {} } as any;
    }

    try {
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
          ...(hit._source as Bundle),
          id: hit._id,
        })),
      };
    } catch (error) {
      this.logger.error(`Search operation failed: ${error.message}`, {
        error: error.meta?.body?.error || error,
      });
      throw new InternalServerErrorException({
        message: 'Search operation failed',
        error: error.message,
        details: error.meta?.body?.error || error,
      });
    }
  }

  async update(id: string, updateBundleInput: UpdateBundleInput): Promise<Bundle> {
    try {
      const existingBundle = await this.findOne(id);

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: {
          doc: {
            ...updateBundleInput,
            modified: new Date().toISOString(),
          },
          doc_as_upsert: false,
        },
        refresh: 'wait_for',
        retry_on_conflict: 5,
      });

      if (response.body.result !== 'updated' && response.body.result !== 'noop') {
        throw new Error(`Failed to update document: ${response.body.result}`);
      }

      const updatedBundle: Bundle = {
        ...existingBundle,
        ...updateBundleInput,
        type: 'bundle',
        spec_version: existingBundle.spec_version || '2.1',
        modified: new Date().toISOString(),
      };

      await this.publishUpdated(updatedBundle);
      return updatedBundle;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      this.logger.error(`Error updating bundle ${id}: ${error.message}`, {
        error: error.meta?.body?.error || error,
      });
      throw new InternalServerErrorException({
        message: 'Error updating bundle',
        error: error.message,
        details: error.meta?.body?.error || error,
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
      return success;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      this.logger.error(`Error deleting bundle ${id}: ${error.message}`, {
        error: error.meta?.body?.error || error,
      });
      throw new InternalServerErrorException({
        message: 'Error deleting bundle',
        error: error.message,
        details: error.meta?.body?.error || error,
      });
    }
  }

  async ensureIndexExists(): Promise<void> {
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
                objects: { type: 'object', enabled: true },
              },
            },
          },
        });
        this.logger.log(`Created index: ${this.index}`);
      }
    } catch (error) {
      this.logger.error(`Failed to initialize index ${this.index}: ${error.message}`, {
        error: error.meta?.body?.error || error,
      });
      throw new InternalServerErrorException({
        message: 'Failed to initialize index',
        error: error.message,
        details: error.meta?.body?.error || error,
      });
    }
  }
}