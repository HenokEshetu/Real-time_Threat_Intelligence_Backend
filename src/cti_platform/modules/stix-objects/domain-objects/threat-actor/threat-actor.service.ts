import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { CreateThreatActorInput, UpdateThreatActorInput } from './threat-actor.input';
import { SearchThreatActorInput } from './threat-actor.resolver';
import { ThreatActor } from './threat-actor.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class ThreatActorService extends BaseStixService<ThreatActor> implements OnModuleInit {
  protected typeName = 'threat-actor';
  private readonly index = 'threat-actors';
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

  async create(createThreatActorInput: CreateThreatActorInput): Promise<ThreatActor> {

    const threatActor: ThreatActor = {
      ...createThreatActorInput,
     
      id: createThreatActorInput.id,
      type: 'threat-actor' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: createThreatActorInput.name, 
      
    };

    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: threatActor.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: threatActor.id });

      const existingDoc = await this.findOne(threatActor.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: threatActor.id,
        body: threatActor,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index threat actor');
      }
      await this.publishCreated(threatActor);
      return threatActor;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create threat actor',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<ThreatActor> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'threat-actor' as const,
        spec_version: source.spec_version || '2.1',
        threat_actor_types:source.threat_actor_types,
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Threat Actor with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch threat actor',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateThreatActorInput: UpdateThreatActorInput): Promise<ThreatActor> {
    try {
      const existingThreatActor = await this.findOne(id);
      const updatedThreatActor: ThreatActor = {
        ...existingThreatActor,
        ...updateThreatActorInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedThreatActor },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update threat actor');
      }
      await this.publishUpdated(updatedThreatActor);
      return updatedThreatActor;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update threat actor',
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
        message: 'Failed to delete threat actor',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchThreatActorInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: ThreatActor[];
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
        } else if (['created', 'modified', 'first_seen', 'last_seen'].includes(key)) {
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
          type: 'threat-actor' as const,
          spec_version: hit._source.spec_version || '2.1',
          threat_actor_types:hit._source.threat_actor_types,
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          name: hit._source.name, // Required field
         
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search threat actors',
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
              dynamic: 'true',
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                name: { type: 'text' },
                description: { type: 'text' },
                threat_actor_types: { type: 'keyword' },
                aliases: { type: 'keyword' },
                first_seen: { type: 'date' },
                last_seen: { type: 'date' },
                roles: { type: 'keyword' },
                goals: { type: 'text' },
                sophistication: { type: 'keyword' },
                resource_level: { type: 'keyword' },
                primary_motivation: { type: 'keyword' },
                secondary_motivations: { type: 'keyword' },
                personal_motivations: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize threat-actors index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}