import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit, Logger } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { CreateCourseOfActionInput, UpdateCourseOfActionInput } from './course-of-action.input';
import { SearchCourseOfActionInput } from './course-of-action.resolver';
import { CourseOfAction } from './course-of-action.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';


@Injectable()
export class CourseOfActionService extends BaseStixService<CourseOfAction> implements OnModuleInit {
  protected typeName = 'course-of-action';
  private readonly index = 'course-of-actions';
  private readonly logger = new Logger(CourseOfActionService.name);

  constructor(
        @Inject(PUB_SUB) pubSub: RedisPubSub,
        @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
      ) {
        super(pubSub);
      }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createCourseOfActionInput: CreateCourseOfActionInput): Promise<CourseOfAction> {
   
    const courseOfAction: CourseOfAction = {
      ...createCourseOfActionInput,
     
      id: createCourseOfActionInput.id,
      type: 'course-of-action' as const,
      spec_version: '2.1',
      created: new Date().  toISOString(),
      modified: new Date().toISOString(),
      name: createCourseOfActionInput.name, // Required field
      
    };



    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: courseOfAction.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: courseOfAction.id });

      const existingDoc = await this.findOne(courseOfAction.id);
      return existingDoc;

    }


    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: courseOfAction.id,
        body: courseOfAction,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index course of action');
      }
      await this.publishCreated(courseOfAction);
      return courseOfAction;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create course of action',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<CourseOfAction> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'course-of-action' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
       
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Course of Action with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch course of action',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateCourseOfActionInput: UpdateCourseOfActionInput): Promise<CourseOfAction> {
    try {
      const existingCourse = await this.findOne(id);
      const updatedCourse: CourseOfAction = {
        ...existingCourse,
        ...updateCourseOfActionInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedCourse },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update course of action');
      }
      await this.publishUpdated(updatedCourse);
      return updatedCourse;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update course of action',
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
      return success;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete course of action',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchCourseOfActionInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: CourseOfAction[];
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
          type: 'course-of-action' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          name: hit._source.name, 
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search courses of action',
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
                x_mitre_modified_by_ref: { type: 'keyword' },
                x_mitre_deprecated: { type: 'boolean' },
                x_mitre_domains: { type: 'keyword' },
                x_mitre_version: { type: 'keyword' },
                x_mitre_attack_spec_version: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize course-of-actions index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}