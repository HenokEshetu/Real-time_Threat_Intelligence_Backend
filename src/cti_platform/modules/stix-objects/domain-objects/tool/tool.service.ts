import { Inject, Injectable, InternalServerErrorException, NotFoundException,OnModuleInit } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { CreateToolInput, UpdateToolInput } from './tool.input';
import { SearchToolInput } from './tool.resolver';
import { Tool } from './tool.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class ToolService extends BaseStixService<Tool> implements OnModuleInit {
  protected typeName = 'tool';
  private readonly index = 'tools';
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

  async create(createToolInput: CreateToolInput): Promise<Tool> {
    
    const tool: Tool = {
      ...createToolInput,
      id: createToolInput.id,
      type: 'tool' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: createToolInput.name,
      
    };


    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: tool.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: tool.id });

      const existingDoc = await this.findOne(tool.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: tool.id,
        body: tool,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index tool');
      }
      await this.publishCreated(tool);
      return tool;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create tool',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<Tool> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'tool' as const,
        spec_version: source.spec_version || '2.1',
        tool_types: source.tool_types,
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
       
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Tool with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch tool',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateToolInput: UpdateToolInput): Promise<Tool> {
    try {
      const existingTool = await this.findOne(id);
      const updatedTool: Tool = {
        ...existingTool,
        ...updateToolInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedTool },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update tool');
      }
      await this.publishUpdated(updatedTool);
      return updatedTool;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update tool',
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
        message: 'Failed to delete tool',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchToolInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Tool[];
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
          type: 'tool' as const,
          spec_version: hit._source.spec_version || '2.1',
          tool_types:hit._source.tool_types,
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          name: hit._source.name, // Required field
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search tools',
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
                tool_types: { type: 'keyword' },
                aliases: { type: 'keyword' },
                kill_chain_phases: { type: 'object' },
                tool_version: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize tools index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}