import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateAttackPatternInput, UpdateAttackPatternInput } from './attack-pattern.input';
import { SearchAttackPatternInput } from './attack-pattern.resolver';
import { AttackPattern } from './attack-pattern.entity';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { BaseStixService } from '../../base-stix.service';
import { Logger } from '@nestjs/common';

@Injectable()
export class AttackPatternService extends BaseStixService<AttackPattern> implements OnModuleInit {
  private readonly index = 'attack-patterns';
  protected typeName = 'attack-pattern';
  private readonly logger = new Logger(AttackPatternService.name);

  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createAttackPatternInput: CreateAttackPatternInput): Promise<AttackPattern> {
    const now = new Date().toISOString();
    const attackPattern: AttackPattern = {
      ...createAttackPatternInput,
      id: createAttackPatternInput.id,
      type: 'attack-pattern',
      spec_version: '2.1',
      created: createAttackPatternInput.created || now,
      modified: createAttackPatternInput.modified || now,
    };


    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: attackPattern.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: attackPattern.id });

      const existingDoc = await this.findOne(attackPattern.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: attackPattern.id,
        body: attackPattern,
        refresh: 'wait_for',
        op_type: 'create'
      });

      if (response.body.result !== 'created') {
        throw new Error(`OpenSearch response error: ${JSON.stringify(response.body)}`);
      }

      await this.publishCreated(attackPattern);
      return attackPattern;
    } catch (error) {
      this.logger.error(`Failed to create attack pattern ${attackPattern.id}`, {
        error: this.safeGetErrorMessage(error),
        input: createAttackPatternInput
      });
      
      if (error.body?.error?.type === 'version_conflict_engine_exception') {
        return this.findOne(attackPattern.id);
      }
      
      throw new InternalServerErrorException({
        message: 'Failed to create attack pattern',
        details: this.safeGetErrorMessage(error)
      });
    }
  }
  private safeGetErrorMessage(error: any): string {
    return JSON.stringify({
      message: error.message,
      status: error.meta?.statusCode,
      body: error.meta?.body?.error,
      stack: error.stack
    }, null, 2);
  }

  async findOne(id: string): Promise<AttackPattern> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'attack-pattern' as const,
        name:source.name,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Attack pattern with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch attack pattern',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateAttackPatternInput: UpdateAttackPatternInput): Promise<AttackPattern> {
    try {
      const existingPattern = await this.findOne(id);
      const updatedPattern: AttackPattern = {
        ...existingPattern,
        ...updateAttackPatternInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedPattern },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update attack pattern');
      }
      await this.publishUpdated(updatedPattern);
      return updatedPattern;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update attack pattern',
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
        message: 'Failed to delete attack pattern',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchAttackPatternInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: AttackPattern[];
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
          name:hit._source.name,
          type: 'attack-pattern' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search attack patterns',
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
              dynamic: "true", 
              properties: {
                // Core STIX fields
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                name: { type: 'text' },
                description: { type: 'text' },
                created_by_ref: { type: 'keyword' }, // ✅ Added missing field
                object_marking_refs: { type: 'keyword' }, // ✅ Added missing field
                revoked: { type: 'boolean' },
                external_references: {
                  type: 'nested',
                  properties: {
                    source_name: { type: 'keyword' },
                    url: { type: 'keyword' },
                    external_id: { type: 'keyword' },
                    description: { type: 'text' }
                  }
                },
                kill_chain_phases: {
                  type: 'nested',
                  properties: {
                    kill_chain_name: { type: 'keyword' },
                    phase_name: { type: 'keyword' }
                  }
                },
  
                // MITRE extensions
                x_mitre_attack_spec_version: { type: 'keyword' },
                x_mitre_modified_by_ref: { type: 'keyword' },
                x_mitre_deprecated: { type: 'boolean' },
                x_mitre_domains: { type: 'keyword' },
                x_mitre_version: { type: 'keyword' },
                x_mitre_aliases: { type: 'keyword' },
                x_mitre_platforms: { type: 'keyword' },
                x_mitre_contributors: { type: 'keyword' },
                x_mitre_detection: { type: 'text' },
                x_mitre_is_subtechnique: { type: 'boolean' },
                x_mitre_data_sources: { type: 'keyword' } // ✅ Added missing field
              }
            }
          }
        });
        this.logger.log(`Created index ${this.index} with MITRE-specific mappings`);
      }
    } catch (error) {
      this.logger.error('Index creation failed', error.stack);
      throw new InternalServerErrorException({
        message: 'Failed to initialize attack patterns index',
        details: this.safeGetErrorMessage(error)
      });
    }
  }
}