import { Injectable, NotFoundException, InternalServerErrorException, OnModuleInit } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { Bundle } from './bundle.entity';
import { CreateBundleInput, UpdateBundleInput } from './bundle.input';
import { SearchBundleInput } from './bundle.resolver';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class BundleService implements OnModuleInit {
  private client: Client;
  private readonly index = 'bundles';
  
  constructor() {
    this.client = new Client({
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
     
      auth: process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD 
        ? {
            username: process.env.OPENSEARCH_USERNAME,
            password: process.env.OPENSEARCH_PASSWORD,
          }
        : undefined,
    });
  }

  async onModuleInit() {
    await this.ensureIndexExists();
  }
  public getClient(): Client {
    return this.client;
  }
  async create(createBundleInput: CreateBundleInput): Promise<Bundle> {
    const id = `bundle--${uuidv4()}`;
    const timestamp = new Date().toISOString();
    const bundle: Bundle = {
      ...createBundleInput,
      id,
      type: 'bundle'
      
    };

    try {
      const response = await this.client.index({
        index: this.index,
        id,
        body: bundle,
        refresh: true, // Make document available for search immediately
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to create document');
      }

      return bundle;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Error creating bundle',
        error: error.message,
      });
    }
  }

  async findOne(id: string): Promise<Bundle> {
    try {
      const response = await this.client.get({
        index: this.index,
        id,
      });

      return {
        ...response.body._source,
        id: response.body._id,
      } as Bundle;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Bundle with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Error fetching bundle',
        error: error.message,
      });
    }
  }
  async searchWithFilters(
    filters: SearchBundleInput,
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Bundle[];
  }> {
    const from = (page - 1) * pageSize;
    const queryBuilder = {
      query: {
        bool: {
          must: [] as any[],
          filter: [] as any[],
        },
      },
      sort: [{ modified: { order: 'desc' } as const }],
    };
  
    for (const [key, value] of Object.entries(filters)) {
      if (value === undefined || value === null) continue;
  
      switch (typeof value) {
        case 'string':
          queryBuilder.query.bool.must.push({
            query_string: {
              query: `${key}:${value}*`,
              default_operator: 'AND',
            },
          });
          break;
        case 'number':
        case 'boolean':
          queryBuilder.query.bool.filter.push({
            term: { [key]: value },
          });
          break;
        case 'object':
          if (value instanceof Date) {
            queryBuilder.query.bool.filter.push({
              range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
            });
          } else if (Array.isArray(value)) {
            queryBuilder.query.bool.filter.push({
              terms: { [key]: value },
            });
          }
          break;
      }
    }
  
    if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
      queryBuilder.query = { match_all: {} } as any;
    }
  
    try {
      const response = await this.client.search({
        index: this.index,
        from,
        size: pageSize,
        body: queryBuilder,
      });
  
      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;
  
      return {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results: response.body.hits.hits.map(hit => ({
          ...(hit._source as Bundle),
          id: hit._id,
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Search operation failed',
        error: error.message,
        details: error.meta?.body?.error,
      });
    }
  }
  

  async update(id: string, updateBundleInput: UpdateBundleInput): Promise<Bundle> {
    try {
      const existingBundle = await this.findOne(id);
      
      const response = await this.client.update({
        index: this.index,
        id,
        body: {
          doc: {
            ...updateBundleInput,
            modified: new Date().toISOString(),
          },
          doc_as_upsert: false,
        },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update document');
      }

      return { ...existingBundle, ...updateBundleInput };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Error updating bundle',
        error: error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.client.delete({
        index: this.index,
        id,
      });

      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Error deleting bundle',
        error: error.message,
      });
    }
  }

 
  async ensureIndexExists(): Promise<void> {
    try {
      const exists = await this.client.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.client.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                type: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                spec_version: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize index',
        error: error.message,
      });
    }
  }
}