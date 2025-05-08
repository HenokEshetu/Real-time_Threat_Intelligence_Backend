import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client,  } from '@opensearch-project/opensearch';
import { CreateObservedDataInput, UpdateObservedDataInput } from './observed-data.input';

import { SearchObservedDataInput } from './observed-data.resolver';
import { ObservedData } from './observed-data.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class ObservedDataService extends BaseStixService<ObservedData> implements OnModuleInit {
  protected typeName = 'observed-data';
  private readonly index = 'observed-data';
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

  async create(createObservedDataInput: CreateObservedDataInput): Promise<ObservedData> {
    
    const observedData: ObservedData = {
      ...createObservedDataInput,
      ...(createObservedDataInput.object_refs ? { object_refs: createObservedDataInput.object_refs } : {}),
      id: createObservedDataInput.id,
      type: 'observed-data' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      first_observed: createObservedDataInput.first_observed, 
      last_observed: createObservedDataInput.last_observed,   
      number_observed: createObservedDataInput.number_observed, 
      
    };

    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: observedData.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: observedData.id });

      const existingDoc = await this.findOne(observedData.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: observedData.id,
        body: observedData,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index observed data');
      }
      await this.publishCreated(observedData);
      return observedData;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create observed data',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<ObservedData> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'observed-data' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        first_observed: source.first_observed, // Required field
        last_observed: source.last_observed,   // Required field
        object_refs:source.object_refs,
        number_observed: source.number_observed, // Required field
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Observed Data with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch observed data',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateObservedDataInput: UpdateObservedDataInput): Promise<ObservedData> {
    try {
      const existingData = await this.findOne(id);
      const updatedData: ObservedData = {
        ...existingData,
        ...updateObservedDataInput,
        modified: new Date(). toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedData },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update observed data');
      }
      await this.publishUpdated(updatedData);
      return updatedData;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update observed data',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });


      const success = response.body.result === 'deleted';
      if (success) {
        await this.publishDeleted(id);
      }

      
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete observed data',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchObservedDataInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: ObservedData[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [], should: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          queryBuilder.query.bool.filter.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          queryBuilder.query.bool.filter.push({ term: { [key]: value } });
        } else if (['created', 'modified', 'first_observed', 'last_observed'].includes(key)) {
          if (typeof value === 'object' && ('gte' in value || 'lte' in value)) {
            queryBuilder.query.bool.filter.push({ range: { [key]: value } });
          } else if (value instanceof Date) {
            queryBuilder.query.bool.filter.push({
              range: { [key]: { gte: value, lte: value } },
            });
          }
        } else if (typeof value === 'string') {
          if (value.includes('*')) {
            queryBuilder.query.bool.must.push({ wildcard: { [key]: value.toLowerCase() } });
          } else if (value.includes('~')) {
            queryBuilder.query.bool.should.push({
              fuzzy: { [key]: { value: value.replace('~', ''), fuzziness: 'AUTO' } },
            });
          } else {
            queryBuilder.query.bool.must.push({ match_phrase: { [key]: value } });
          }
        }
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length && !queryBuilder.query.bool.should.length) {
        queryBuilder.query = { match_all: {} };
      } else if (queryBuilder.query.bool.should.length > 0) {
        queryBuilder.query.bool.minimum_should_match = 1;
      }

      const response = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'number'
        ? response.body.hits.total
        : response.body.hits.total?.value ?? 0;

      return {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results: response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          type: 'observed-data' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          first_observed: hit._source.first_observed, // Required field
          last_observed: hit._source.last_observed,   // Required field
          number_observed: hit._source.number_observed, // Required field
          object_refs: hit._source.object_refs,
         
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search observed data',
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
                first_observed: { type: 'date' },
                last_observed: { type: 'date' },
                number_observed: { type: 'integer' },
                object_refs: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize observed-data index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}