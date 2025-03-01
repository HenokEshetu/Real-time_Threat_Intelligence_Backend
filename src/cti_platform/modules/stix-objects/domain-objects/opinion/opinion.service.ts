import { Injectable } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateOpinionInput, UpdateOpinionInput } from './opinion.input';
import { v4 as uuidv4 } from 'uuid';
import { Opinion } from './opinion.entity';
import { SearchOpinionInput } from './opinion.resolver';
@Injectable()
export class OpinionService {
  private index = 'opinions';
  private opensearchClient: Client;

  constructor() {
    this.opensearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createOpinionInput: CreateOpinionInput): Promise<any> {
    const opinion = {
      ...createOpinionInput,
      id: `opinion--${uuidv4()}`,
    };

    const response = await this.opensearchClient.index({
      index: this.index,
      id: opinion.id,
      body: opinion,
      refresh: true, // ✅ Fixed
    });

    return response.body;
  }

  async searchOpinionWithDynamicFilters(
    filters?: SearchOpinionInput,
    page = 1,
    pageSize = 10,
    sortField?: string,
    sortOrder: 'asc' | 'desc' = 'desc',
    fullTextSearch?: string,
  ): Promise<Opinion[]> {
    const must: any[] = [];
    const should: any[] = [];
    const mustNot: any[] = [];

    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (typeof value === 'string') {
          must.push({ match_phrase: { [key]: value } });
        } else if (typeof value === 'number') {
          must.push({ term: { [key]: value } });
        } else if (Array.isArray(value)) {
          should.push({ terms: { [key]: value } });
        } else if (typeof value === 'object' && value.range) {
          must.push({ range: { [key]: value.range } });
        }
      });
    }

    if (fullTextSearch) {
      should.push({
        multi_match: {
          query: fullTextSearch,
          fields: ['title', 'explanation', 'author'],
          fuzziness: 'AUTO',
        },
      });
    }

    const response = await this.opensearchClient.search({
      index: this.index, // ✅ Fixed index placement
      body: {
        query: {
          bool: {
            must,
            should: should.length > 0 ? should : undefined,
            must_not: mustNot.length > 0 ? mustNot : undefined,
          },
        },
        from: (page - 1) * pageSize,
        size: pageSize,
        sort: sortField ? [{ [sortField]: { order: sortOrder } }] : [],
      },
    });

    const hits = response.body.hits?.hits ?? [];

    return hits.map((hit: any) => ({
      id: hit._id,
      ...(hit._source as Opinion),
    }));
  }

  async findOne(id: string): Promise<any> {
    try {
      const response = await this.opensearchClient.get({
        index: this.index,
        id,
      });
      return response.body._source;
    } catch (error) {
      return null;
    }
  }

  async update(id: string, updateOpinionInput: UpdateOpinionInput): Promise<any> {
    await this.opensearchClient.update({
      index: this.index,
      id,
      body: { doc: updateOpinionInput },
      refresh: true, // ✅ Fixed
    });

    return this.findOne(id);
  }

  async remove(id: string): Promise<boolean> {
    try {
      await this.opensearchClient.delete({
        index: this.index,
        id,
        refresh: true, // ✅ Fixed
      });
      return true;
    } catch (error) {
      return false;
    }
  }
}
