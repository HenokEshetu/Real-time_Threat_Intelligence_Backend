import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client } from '@opensearch-project/opensearch';
import { CreateIdentityInput, UpdateIdentityInput } from './identity.input';
import { SearchIdentityInput } from './identity.resolver';
@Injectable()
export class IdentityService {
  private readonly index = 'identities'; // OpenSearch index name

  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create identity
  async create(createIdentityInput: CreateIdentityInput): Promise<any> {
    const identity = {
      id: `identity--${uuidv4()}`,
      type: 'identity',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createIdentityInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: identity.id,
        body: identity,
        refresh: 'wait_for',
      });

      return identity;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create identity: ${error.message}`);
    }
  }

  // Find identity by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Identity with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching identity: ${error.message}`);
    }
  }

  // Update identity
  async update(id: string, updateIdentityInput: UpdateIdentityInput): Promise<any> {
    try {
      const existingIdentity = await this.findOne(id);

      const updatedIdentity = {
        ...existingIdentity,
        ...updateIdentityInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedIdentity,
        refresh: 'wait_for',
      });

      return updatedIdentity;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update identity: ${error.message}`);
    }
  }

  // Delete identity
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
        throw new NotFoundException(`Identity with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete identity: ${error.message}`);
    }
  }

  // Dynamic Search with Filters
  async searchIdentityWithFilters(filters: SearchIdentityInput, page = 1, pageSize = 10): Promise<any> {
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
      throw new InternalServerErrorException(`Error searching identities in OpenSearch: ${error.message}`);
    }
  }
}
