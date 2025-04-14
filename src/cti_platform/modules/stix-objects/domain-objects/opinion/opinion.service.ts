import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateOpinionInput, UpdateOpinionInput } from './opinion.input';
import { v4 as uuidv4 } from 'uuid';
import { Opinion } from './opinion.entity';
import { SearchOpinionInput } from './opinion.resolver';

@Injectable()
export class OpinionService implements OnModuleInit {
  private readonly index = 'opinions';
  private readonly opensearchClient: Client;

  constructor() {
    const clientOptions: ClientOptions = {
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
      ssl: process.env.OPENSEARCH_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      auth: process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD
        ? {
            username: process.env.OPENSEARCH_USERNAME,
            password: process.env.OPENSEARCH_PASSWORD,
          }
        : undefined,
    };
    this.opensearchClient = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createOpinionInput: CreateOpinionInput): Promise<Opinion> {
    const opinion: Opinion = {
      id: `opinion--${uuidv4()}`,
      type: 'opinion' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      opinion: createOpinionInput.opinion, // Required field
      ...createOpinionInput,
      ...(createOpinionInput.object_refs ? { object_refs: createOpinionInput.object_refs } : {}),
    };

    try {
      const response = await this.opensearchClient.index({
        index: this.index,
        id: opinion.id,
        body: opinion,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index opinion');
      }
      return opinion;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create opinion',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<Opinion> {
    try {
      const response = await this.opensearchClient.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        id: response.body._id,
        type: 'opinion' as const,
        spec_version: source.spec_version || '2.1',
        explanation:source.explanation,
        object_refs:source.object_refs,

        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        opinion: source.opinion, // Required field
        ...source,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Opinion with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch opinion',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateOpinionInput: UpdateOpinionInput): Promise<Opinion> {
    try {
      const existingOpinion = await this.findOne(id);
      const updatedOpinion: Opinion = {
        ...existingOpinion,
        ...updateOpinionInput,
        modified: new Date().toISOString(),
      };

      const response = await this.opensearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedOpinion },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update opinion');
      }

      return updatedOpinion;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update opinion',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.opensearchClient.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete opinion',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchOpinionInput = {},
    page: number = 1,
    pageSize: number = 10,
    sortField: keyof Opinion = 'modified',
    sortOrder: 'asc' | 'desc' = 'desc',
    fullTextSearch?: string
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Opinion[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [], should: [] } },
        sort: [{ [sortField]: { order: sortOrder } }],
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
              range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
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

      if (fullTextSearch) {
        queryBuilder.query.bool.should.push({
          multi_match: {
            query: fullTextSearch,
            fields: ['explanation', 'authors'],
            fuzziness: 'AUTO',
          },
        });
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length && !queryBuilder.query.bool.should.length) {
        queryBuilder.query = { match_all: {} };
      } else if (queryBuilder.query.bool.should.length > 0) {
        queryBuilder.query.bool.minimum_should_match = 1;
      }

      const response = await this.opensearchClient.search({
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
          id: hit._id,
          type: 'opinion' as const,
          spec_version: hit._source.spec_version || '2.1',
          explanation:hit._source.explanation,
          object_refs:hit._source.object_refs,
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          opinion: hit._source.opinion, // Required field
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search opinions',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.opensearchClient.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.opensearchClient.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                opinion: { type: 'keyword' },
                explanation: { type: 'text' },
                authors: { type: 'keyword' },
                object_refs: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize opinions index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}