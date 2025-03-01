import { Injectable,  InternalServerErrorException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateObservedDataInput, UpdateObservedDataInput } from './observed-data.input';
import { v4 as uuidv4 } from 'uuid';
import { SearchObservedDataInput } from './observed-data.resolver';
@Injectable()
export class ObservedDataService {
  private readonly index = 'observed-data';

  private openSearchClient: Client;

  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createObservedDataInput: CreateObservedDataInput): Promise<any> {
    const id = `observed-data--${uuidv4()}`;
    const observedData = {
      ...createObservedDataInput,
      id,
    };

    await this.openSearchClient.index({
      index: this.index,
      id,
      body: observedData,
    });

    return observedData;
  }

  async searchObservedDataWithFilters(filters: SearchObservedDataInput, page = 1, pageSize = 10): Promise<any> {
    try {
      const mustQueries = [];
      const shouldQueries = [];
      const filterQueries = [];

      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          // Handle array values using "terms" query
          mustQueries.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          // Handle exact match using "term"
          mustQueries.push({ term: { [key]: value } });
        } else if (['created', 'modified'].includes(key)) {
          // Handle range queries for date fields
          if (typeof value === 'object' && ('gte' in value || 'lte' in value)) {
            filterQueries.push({ range: { [key]: value } });
          } else {
            filterQueries.push({ range: { [key]: { gte: value } } });
          }
        } else if (typeof value === 'string') {
          if (value.includes('*')) {
            // Wildcard search (supports partial match with `*`)
            mustQueries.push({ wildcard: { [key]: value.toLowerCase() } });
          } else if (value.includes('~')) {
            // Fuzzy search (supports typo tolerance)
            shouldQueries.push({ fuzzy: { [key]: { value, fuzziness: 'AUTO' } } });
          } else {
            // Default to exact phrase match
            mustQueries.push({ match_phrase: { [key]: value } });
          }
        }
      }

      const query: any = { bool: {} };
      if (mustQueries.length > 0) query.bool.must = mustQueries;
      if (shouldQueries.length > 0) query.bool.should = shouldQueries;
      if (filterQueries.length > 0) query.bool.filter = filterQueries;
      if (Object.keys(query.bool).length === 0) query.bool.must = [{ match_all: {} }];

      const { body } = await this.openSearchClient.search({
        index: this.index,
        from: (page - 1) * pageSize,
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
      throw new InternalServerErrorException(`Error searching observed data: ${error.message}`);
    }
  }

  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({ index: this.index, id });
      return body._source;
    } catch (error) {
      if (error.meta.statusCode === 404) return null;
      throw error;
    }
  }

  async update(id: string, updateObservedDataInput: UpdateObservedDataInput): Promise<any> {
    await this.openSearchClient.update({
      index: this.index,
      id,
      body: {
        doc: updateObservedDataInput,
      },
    });

    return this.findOne(id);
  }

  async remove(id: string): Promise<boolean> {
    try {
      await this.openSearchClient.delete({ index: this.index, id });
      return true;
    } catch (error) {
      if (error.meta.statusCode === 404) return false;
      throw error;
    }
  }
}
