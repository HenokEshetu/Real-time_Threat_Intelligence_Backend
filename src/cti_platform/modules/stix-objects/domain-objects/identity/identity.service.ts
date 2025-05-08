import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client,  } from '@opensearch-project/opensearch';
import { CreateIdentityInput, UpdateIdentityInput } from './identity.input';
import { SearchIdentityInput } from './identity.resolver';
import { Identity } from './identity.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class IdentityService extends BaseStixService<Identity> implements OnModuleInit {
  protected typeName = 'identity';
  private readonly index = 'identities';
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

  async create(createIdentityInput: CreateIdentityInput): Promise<Identity> {
    
    const identity: Identity = {
      ...createIdentityInput,
      id: createIdentityInput.id,
      type: 'identity' as const,
      spec_version: '2.1',
      created: new Date().  toISOString(),
      modified: new Date().toISOString(),
      name: createIdentityInput.name, // Required field
      
    };



    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: identity.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: identity.id });

      const existingDoc = await this.findOne(identity.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: identity.id,
        body: identity,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index identity');
      }
      await this.publishCreated(identity);
      return identity;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create identity',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<Identity> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'identity' as const,
        identity_class: source.identity_class,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Identity with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch identity',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateIdentityInput: UpdateIdentityInput): Promise<Identity> {
    try {
      const existingIdentity = await this.findOne(id);
      const updatedIdentity: Identity = {
        ...existingIdentity,
        ...updateIdentityInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedIdentity },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update identity');
      }
      await this.publishUpdated(updatedIdentity);
      return updatedIdentity;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update identity',
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
        message: 'Failed to delete identity',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchIdentityInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Identity[];
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
        } else if (['created', 'modified'].includes(key)) {
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
          type: 'identity' as const,
          identity_class: hit._source.identity_class,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          name: hit._source.name, // Required field
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search identities',
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
                name: { type: 'text' },
                description: { type: 'text' },
                identity_class: { type: 'keyword' },
                sectors: { type: 'keyword' },
                contact_information: { type: 'text' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize identities index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}