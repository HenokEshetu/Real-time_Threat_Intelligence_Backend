import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit, Logger } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { CreateAutonomousSystemInput, UpdateAutonomousSystemInput } from './autonomous-system.input';
import { AutonomousSystem } from './autonomous-system.entity';
import { SearchAutonomousSystemInput } from './autonomous-system.resolver';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@Injectable()
export class AutonomousSystemService extends BaseStixService<AutonomousSystem> implements OnModuleInit {
  protected typeName = 'autonomous-system';
  private readonly index = 'autonomous-systems';
  private readonly logger = new Logger(AutonomousSystemService.name);


  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async searchWithFilters(
    searchParams: SearchAutonomousSystemInput = {},
    from: number = 0,
    size: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: AutonomousSystem[];
  }> {
    try {
      const queryBuilder: { query: any; sort?: any[] } = {
        query: {
          bool: {
            must: [],
            filter: [],
          },
        },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'number':
            queryBuilder.query.bool.filter.push({ term: { [key]: value } });
            break;
          case 'created':
          case 'modified':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value, lte: value } },
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
        size,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;

      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results: response.body.hits.hits.map(hit => ({
          id: hit._id,
          number: hit._source.number,
          type: 'autonomous-system' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Error fetching Autonomous Systems',
        details: error.meta?.body?.error || error.message,
      });
    }
  }


  async create(createAutonomousSystemInput: CreateAutonomousSystemInput): Promise<AutonomousSystem> {
    const now = new Date();



    const doc: AutonomousSystem = {
      ...createAutonomousSystemInput,
      id: createAutonomousSystemInput.id,
      type: 'autonomous-system' as const,
      spec_version: '2.1',
      created: now.toISOString(),
      modified: now.toISOString(),
    }; ``


    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: doc.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: doc.id });

      const existingDoc = await this.findOneById(doc.id);
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
        throw new Error('Failed to index document');
      }
      await this.publishCreated(doc);
      return doc;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create Autonomous System',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateAutonomousSystemInput: UpdateAutonomousSystemInput): Promise<AutonomousSystem> {
    try {
      const existing = await this.findOneById(updateAutonomousSystemInput.id);
      const updatedDoc = {
        ...updateAutonomousSystemInput,
        modified: new Date(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update document');
      }
      await this.publishUpdated({ ...updatedDoc, modified: updatedDoc.modified.toISOString() });
      return { ...existing, ...updatedDoc, modified: updatedDoc.modified.toISOString() };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update Autonomous System',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOneById(id: string): Promise<AutonomousSystem> {
    try {
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;

      return {
        ...source,
        id,
        number: source.number,
        type: 'autonomous-system' as const,
        spec_version: '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),

      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Autonomous System with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch Autonomous System',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByNumber(number: number): Promise<AutonomousSystem> {
    try {
      const response = await this.openSearchService.search({
        index: this.index,
        body: {
          query: { term: { number } },
        },
      });

      if (!response.body.hits.hits.length) {
        throw new NotFoundException(`Autonomous System with number ${number} not found`);
      }

      const hit = response.body.hits.hits[0];
      return {
        ...hit._source,
        id: hit._id,
        number: hit._source.number,
        type: 'autonomous-system' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date(),
        modified: hit._source.modified || new Date(),

      };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to find Autonomous System by number',
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
        message: 'Failed to delete Autonomous System',
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
                number: { type: 'integer' },
                name: { type: 'text' },
                rir: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize autonomous-systems index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}