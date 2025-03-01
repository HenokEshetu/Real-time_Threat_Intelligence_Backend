import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { v4 as uuidv4 } from 'uuid';
import { CreateCourseOfActionInput, UpdateCourseOfActionInput } from './course-of-action.input';
import { SearchCourseOfActionInput } from './course-of-action.resolver';
@Injectable()
export class CourseOfActionService {
  private readonly index = 'course-of-actions'; // OpenSearch index name

  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new Course of Action
  async create(createCourseOfActionInput: CreateCourseOfActionInput): Promise<any> {
    const courseOfAction = {
      id: `course-of-action--${uuidv4()}`,
      type: 'course-of-action',
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createCourseOfActionInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: courseOfAction.id,
        body: courseOfAction,
        refresh: 'wait_for',
      });

      return courseOfAction;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create course of action: ${error.message}`);
    }
  }

  // Find a course of action by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Course of Action with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching course of action: ${error.message}`);
    }
  }

  // Update a course of action
  async update(id: string, updateCourseOfActionInput: UpdateCourseOfActionInput): Promise<any> {
    try {
      const existingCourse = await this.findOne(id);

      const updatedCourse = {
        ...existingCourse,
        ...updateCourseOfActionInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedCourse,
        refresh: 'wait_for',
      });

      return updatedCourse;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update course of action: ${error.message}`);
    }
  }

  // Delete a course of action
  async remove(id: string): Promise<boolean> {
    try {
      const { body } = await this.openSearchService.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });

      return body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Course of Action with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete course of action: ${error.message}`);
    }
  }

  // 🔎 Search with dynamic filters
  async searchWithFilters(filters: SearchCourseOfActionInput, page = 1, pageSize = 10): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];
      const shouldQueries = [];
      const filterQueries = [];

      // Construct dynamic search queries
      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          mustQueries.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          mustQueries.push({ term: { [key]: value } });
        } else if (['created', 'modified'].includes(key)) {
          // Handle date range filtering
          if (typeof value === 'object' && ('gte' in value || 'lte' in value)) {
            filterQueries.push({ range: { [key]: value } });
          } else {
            filterQueries.push({ range: { [key]: { gte: value } } });
          }
        } else if (typeof value === 'string') {
          if (value.includes('*')) {
            mustQueries.push({ wildcard: { [key]: value.toLowerCase() } });
          } else if (value.includes('~')) {
            shouldQueries.push({ fuzzy: { [key]: { value, fuzziness: 'AUTO' } } });
          } else {
            mustQueries.push({ match_phrase: { [key]: value } });
          }
        }
      }

      // Construct OpenSearch query
      const query: any = { bool: {} };

      if (mustQueries.length > 0) query.bool.must = mustQueries;
      if (shouldQueries.length > 0) query.bool.should = shouldQueries;
      if (filterQueries.length > 0) query.bool.filter = filterQueries;

      if (Object.keys(query.bool).length === 0) {
        query.bool.must = [{ match_all: {} }];
      }

      // Execute OpenSearch Query
      const { body } = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: {
          query,
          sort: [{ created: { order: 'desc' } }],
        },
      });

      // Safely extract `total`
      const total = typeof body.hits.total === 'number' ? body.hits.total : body.hits.total?.value ?? 0;

      return {
        total,
        page,
        pageSize,
        results: body.hits.hits.map((hit) => ({
          id: hit._id,
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException(`Error searching course of actions in OpenSearch: ${error.message}`);
    }
  }
}
