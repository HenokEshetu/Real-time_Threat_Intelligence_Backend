import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit, Inject } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client,  } from '@opensearch-project/opensearch';
import { CreateInfrastructureInput, UpdateInfrastructureInput } from './infrastructure.input';
import { SearchInfrastructureInput } from './infrastructure.resolver';
import { Infrastructure } from './infrastructure.entity';
import { BaseStixService } from '../../base-stix.service';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { generateStixId } from '../../stix-id-generator';
import { Logger } from '@nestjs/common';

@Injectable()
export class InfrastructureService extends BaseStixService<Infrastructure> implements OnModuleInit {
  private readonly logger = new Logger(InfrastructureService.name);
  private readonly index = 'infrastructures';
  protected typeName = 'infrastructure';

  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }
  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createInfrastructureInput: CreateInfrastructureInput): Promise<Infrastructure> {
    
    const infrastructure: Infrastructure = {
      ...createInfrastructureInput,
     
      id: createInfrastructureInput.id,
      type: 'infrastructure' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: createInfrastructureInput.name, // Required field
      
    };
    // Check if document already exists
      const exists = await this.openSearchService.exists({
        index: this.index,
        id: infrastructure.id,
      });

      if (exists.body) {
        this.logger?.warn(`Document already exists`, { id: infrastructure.id });

        const existingDoc = await this.findOne(infrastructure.id);
        return existingDoc;

      }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: infrastructure.id,
        body: infrastructure,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index infrastructure');
      }
      await this.publishCreated(infrastructure);
      return infrastructure;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create infrastructure',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<Infrastructure> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'infrastructure' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Infrastructure with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch infrastructure',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateInfrastructureInput: UpdateInfrastructureInput): Promise<Infrastructure> {
    try {
      const existingInfrastructure = await this.findOne(id);
      const updatedInfrastructure: Infrastructure = {
        ...existingInfrastructure,
        ...updateInfrastructureInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedInfrastructure },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update infrastructure');
      }
      await this.publishUpdated(updatedInfrastructure);
      return updatedInfrastructure;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update infrastructure',
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
      return success;;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete infrastructure',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchInfrastructureInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Infrastructure[];
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
          type: 'infrastructure' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          name: hit._source.name, // Required field
         
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search infrastructures',
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
                infrastructure_types: { type: 'keyword' },
                aliases: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize infrastructures index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}