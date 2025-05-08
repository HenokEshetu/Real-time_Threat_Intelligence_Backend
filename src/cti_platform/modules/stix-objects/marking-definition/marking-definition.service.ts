import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import {
  CreateMarkingDefinitionInput,
  UpdateMarkingDefinitionInput,
  SearchMarkingDefinitionInput,
} from './marking-definition.input';
import { MarkingDefinition } from './marking-definition.entity';
import { BaseStixService } from '../base-stix.service';
import { PUB_SUB } from '../../pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';


@Injectable()
export class MarkingDefinitionService extends BaseStixService<MarkingDefinition> implements OnModuleInit {
  protected typeName = 'marking-definition';
  private readonly index = 'marking-definitions';
  private readonly logger = console; 


  constructor(
          @Inject(PUB_SUB) pubSub: RedisPubSub,
          @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
        ) {
          super(pubSub);
        }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createMarkingDefinitionInput: CreateMarkingDefinitionInput): Promise<MarkingDefinition> {

    const markingDefinition: MarkingDefinition = {
      ...createMarkingDefinitionInput,
      id: createMarkingDefinitionInput.id,
      type: 'marking-definition' as const,
      spec_version: '2.1',
      definition_type: createMarkingDefinitionInput.definition_type,
      definition: createMarkingDefinitionInput.definition || {}, 
    };


    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: markingDefinition.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: markingDefinition.id });
      
      const existingDoc = await this.findOne(markingDefinition.id);
      return existingDoc;
    }
    
    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: markingDefinition.id,
        body: markingDefinition,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index marking definition');
      }
      await this.publishCreated(markingDefinition);
      return markingDefinition;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create marking definition',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<MarkingDefinition> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'marking-definition' as const,
        spec_version: source.spec_version || '2.1',
        definition_type: source.definition_type,
        definition: source.definition || {}, // Ensure 'definition' is always provided
        created: new Date(source.created).toISOString(),
        modified: new Date(source.modified).toISOString(),
        created_by_ref: source.created_by_ref,
        object_marking_refs: source.object_marking_refs,
        external_references: source.external_references,
        granular_markings: source.granular_markings,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Marking Definition with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch marking definition',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateMarkingDefinitionInput: UpdateMarkingDefinitionInput): Promise<MarkingDefinition> {
    try {
      const existingMarkingDefinition = await this.findOne(id);
      const updatedMarkingDefinition: MarkingDefinition = {
        ...existingMarkingDefinition,
        ...updateMarkingDefinitionInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedMarkingDefinition },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update marking definition');
      }
      await this.publishUpdated(updatedMarkingDefinition);
      return updatedMarkingDefinition;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update marking definition',
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
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete marking definition',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchMarkingDefinitionInput = {},
    page: number = 1,
    pageSize: number = 10,
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: MarkingDefinition[];
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

      if (
        !queryBuilder.query.bool.must.length &&
        !queryBuilder.query.bool.filter.length &&
        !queryBuilder.query.bool.should.length
      ) {
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
          type: 'marking-definition' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: new Date(hit._source.created).toISOString(),
          modified: new Date(hit._source.modified).toISOString(),
          definition_type: hit._source.definition_type,
          created_by_ref: hit._source.created_by_ref,
          definition: hit._source.definition || {},
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search marking definitions',
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
                definition_type: { type: 'keyword' },
                definition: { type: 'object', enabled: true },
                created_by_ref: { type: 'keyword' },
                object_marking_refs: { type: 'keyword' },
                external_references: { type: 'keyword' },
                granular_markings: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize marking definitions index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}