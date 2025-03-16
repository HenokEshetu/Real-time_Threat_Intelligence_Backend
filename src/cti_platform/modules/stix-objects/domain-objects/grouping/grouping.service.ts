import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { v4 as uuidv4 } from 'uuid';
import { CreateGroupingInput, UpdateGroupingInput } from './grouping.input';
import { SearchGroupingInput } from './grouping.resolver';
@Injectable()
export class GroupingService {
  private readonly index = 'groupings'; // OpenSearch index name

  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  // 📌 Create a new Grouping
  async create(createGroupingInput: CreateGroupingInput): Promise<any> {
    const grouping = {
      id: `grouping--${uuidv4()}`,
      type: 'grouping',
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createGroupingInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: grouping.id,
        body: grouping,
        refresh: 'wait_for',
      });

      return grouping;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create grouping: ${error.message}`);
    }
  }

  // 📌 Find a Grouping by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Grouping with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching grouping: ${error.message}`);
    }
  }

  // 📌 Update an existing Grouping
  async update(id: string, updateGroupingInput: UpdateGroupingInput): Promise<any> {
    try {
      const existingGrouping = await this.findOne(id);

      const updatedGrouping = {
        ...existingGrouping,
        ...updateGroupingInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedGrouping,
        refresh: 'wait_for',
      });

      return updatedGrouping;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update grouping: ${error.message}`);
    }
  }

  // 📌 Delete a Grouping by ID
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
        throw new NotFoundException(`Grouping with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete grouping: ${error.message}`);
    }
  }

  // 📌 Search Groupings with Filters (Dynamic Search)
  async searchWithFilters(filters: SearchGroupingInput, page = 1, pageSize = 10): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];
      const shouldQueries = [];
      const filterQueries = [];

      // 🔍 Construct dynamic search queries
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

      // 🏗 Construct OpenSearch query
      const query: any = { bool: {} };

      if (mustQueries.length > 0) query.bool.must = mustQueries;
      if (shouldQueries.length > 0) query.bool.should = shouldQueries;
      if (filterQueries.length > 0) query.bool.filter = filterQueries;

      if (Object.keys(query.bool).length === 0) {
        query.bool.must = [{ match_all: {} }];
      }

      // 🔎 Execute OpenSearch Query
      const { body } = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: {
          query,
          sort: [{ created: { order: 'desc' } }],
        },
      });

      // Extract `total` safely
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
      throw new InternalServerErrorException(`Error searching groupings in OpenSearch: ${error.message}`);
    }
  }
}
