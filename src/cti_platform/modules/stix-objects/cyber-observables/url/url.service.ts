import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateUrlInput, UpdateUrlInput } from './url.input';
import { Url } from './url.entity';
import { SearchUrlInput } from './url.resolver';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';


@Injectable()
export class UrlService extends BaseStixService<Url> implements OnModuleInit {
  protected typeName = 'url';
  private readonly index = 'urls';
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

  async create(createUrlInput: CreateUrlInput): Promise<Url> {
    
    const now = new Date().toISOString();

    const doc: Url = {
      id: createUrlInput.id,
      type: 'url',
      spec_version: '2.1',
      created: now,
      modified: now,
      value: createUrlInput.value,
      labels: createUrlInput.labels || undefined,
      external_references: createUrlInput.external_references || undefined,
      
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
        throw new Error(`Failed to index URL document: ${response.body.result}`);
      }

      await this.publishCreated(doc);
      return doc;
    } catch (error) {
      const errorDetails = error?.meta?.body?.error || error?.message || 'Unknown error';
      throw new InternalServerErrorException({
        message: `Failed to create URL with ID ${doc.id}`,
        details: errorDetails,
        errorCode: error?.meta?.statusCode,
      });
    }
  }

  async findOne(id: string): Promise<Url> {
    try {
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;
      return {
        id: response.body._id,
        type: 'url',
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        value: source.value,
        labels: source.labels || undefined,
        external_references: source.external_references || undefined,
        object_marking_refs: source.object_marking_refs || undefined,
      };
    } catch (error) {
      if (error?.meta?.statusCode === 404) {
        throw new NotFoundException(`URL with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: `Failed to fetch URL with ID ${id}`,
        details: error?.meta?.body?.error || error?.message,
        errorCode: error?.meta?.statusCode,
      });
    }
  }

  async update(id: string, updateUrlInput: UpdateUrlInput): Promise<Url> {
    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<Url> = {
        ...updateUrlInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error(`Failed to update URL document: ${response.body.result}`);
      }

      const updatedResponse = await this.openSearchService.get({ index: this.index, id });
      const updatedUrl: Url = {
        id: updatedResponse.body._id,
        type: 'url',
        spec_version: updatedResponse.body._source.spec_version || '2.1',
        created: updatedResponse.body._source.created || new Date().toISOString(),
        modified: updatedResponse.body._source.modified || new Date().toISOString(),
        value: updatedResponse.body._source.value,
        labels: updatedResponse.body._source.labels || undefined,
        external_references: updatedResponse.body._source.external_references || undefined,
        object_marking_refs: updatedResponse.body._source.object_marking_refs || undefined,
      };

      await this.publishUpdated(updatedUrl);
      return updatedUrl; // Return the fetched updated document
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: `Failed to update URL with ID ${id}`,
        details: error?.meta?.body?.error || error?.message,
        errorCode: error?.meta?.statusCode,
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
      return success;
    } catch (error) {
      if (error?.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: `Failed to delete URL with ID ${id}`,
        details: error?.meta?.body?.error || error?.message,
        errorCode: error?.meta?.statusCode,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchUrlInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Url[];
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
          id: hit._id,
          type: 'url',
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          value: hit._source.value,
          labels: hit._source.labels || undefined,
          external_references: hit._source.external_references || undefined,
          object_marking_refs: hit._source.object_marking_refs || undefined,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search URLs',
        details: error?.meta?.body?.error || error?.message,
        errorCode: error?.meta?.statusCode,
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
                value: { type: 'keyword' },
                labels: { type: 'keyword' },
                external_references: { type: 'nested' },
                object_marking_refs: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize URLs index',
        details: error?.meta?.body?.error || error?.message,
        errorCode: error?.meta?.statusCode,
      });
    }
  }
}