import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { v4 as uuidv4 } from 'uuid';
import { CreateIntrusionSetInput, UpdateIntrusionSetInput } from './intrusion-set.input';
import { SearchIntrusionSetInput } from './intrusion-set.resolver';
@Injectable()
export class IntrusionSetService {
  private readonly index = 'intrusion-sets'; // OpenSearch index name

  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create IntrusionSet
  async create(createIntrusionSetInput: CreateIntrusionSetInput): Promise<any> {
    const intrusionSet = {
      id: `intrusion-set--${uuidv4()}`,
      type: 'intrusion-set',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createIntrusionSetInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: intrusionSet.id,
        body: intrusionSet,
        refresh: 'wait_for',
      });

      return intrusionSet;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create intrusion set: ${error.message}`);
    }
  }

  // Find IntrusionSet by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Intrusion set with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching intrusion set: ${error.message}`);
    }
  }

  // Update IntrusionSet
  async update(id: string, updateIntrusionSetInput: UpdateIntrusionSetInput): Promise<any> {
    try {
      const existingIntrusionSet = await this.findOne(id);

      const updatedIntrusionSet = {
        ...existingIntrusionSet,
        ...updateIntrusionSetInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedIntrusionSet,
        refresh: 'wait_for',
      });

      return updatedIntrusionSet;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update intrusion set: ${error.message}`);
    }
  }

  // Delete IntrusionSet
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
        throw new NotFoundException(`Intrusion set with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete intrusion set: ${error.message}`);
    }
  }

  // Search IntrusionSets with Filters
  async searchIntrusionSetWithFilters(filters: SearchIntrusionSetInput, page = 1, pageSize = 10): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];
      const shouldQueries = [];
      const filterQueries = [];

      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          mustQueries.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          mustQueries.push({ term: { [key]: value } });
        } else if (['created', 'modified'].includes(key)) {
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

      const query: any = { bool: {} };
      if (mustQueries.length > 0) query.bool.must = mustQueries;
      if (shouldQueries.length > 0) query.bool.should = shouldQueries;
      if (filterQueries.length > 0) query.bool.filter = filterQueries;
      if (Object.keys(query.bool).length === 0) query.bool.must = [{ match_all: {} }];

      const { body } = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: {
          query,
          sort: [{ created: { order: 'desc' } }],
        },
      });

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
      throw new InternalServerErrorException(`Error searching intrusion sets in OpenSearch: ${error.message}`);
    }
  }
}
