import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client } from '@opensearch-project/opensearch';
import { CreateIndicatorInput, UpdateIndicatorInput } from './indicator.input';
import { SearchIndicatorInput } from './indicator.resolver';
@Injectable()
export class IndicatorService {
  private readonly index = 'indicators';

  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createIndicatorInput: CreateIndicatorInput): Promise<any> {
    const indicator = {
      id: `indicator--${uuidv4()}`,
      type: 'indicator',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createIndicatorInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: indicator.id,
        body: indicator,
        refresh: 'wait_for',
      });

      return indicator;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create indicator: ${error.message}`);
    }
  }

  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Indicator with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching indicator: ${error.message}`);
    }
  }

  async update(id: string, updateIndicatorInput: UpdateIndicatorInput): Promise<any> {
    try {
      const existingIndicator = await this.findOne(id);

      const updatedIndicator = {
        ...existingIndicator,
        ...updateIndicatorInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedIndicator,
        refresh: 'wait_for',
      });

      return updatedIndicator;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update indicator: ${error.message}`);
    }
  }

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
        throw new NotFoundException(`Indicator with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete indicator: ${error.message}`);
    }
  }

  async searchIndicatorWithFilters(filters: SearchIndicatorInput, page = 1, pageSize = 10): Promise<any> {
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
      throw new InternalServerErrorException(`Error searching indicators in OpenSearch: ${error.message}`);
    }
  }
}
