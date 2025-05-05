import { Injectable, NotFoundException, InternalServerErrorException, OnModuleInit } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { Bundle } from './bundle.entity';
import { CreateBundleInput, UpdateBundleInput } from './bundle.input';
import { SearchBundleInput } from './bundle.resolver';
import { v5 as uuidv5 } from 'uuid';

// Define the UUID namespace (DNS namespace in this example)
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

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
    try {
      // Validate input first
      this.validateBundleInput(createBundleInput);

      // Generate deterministic ID based on bundle content
      const idSeed = [
        createBundleInput.objects?.length.toString() || '0',
        createBundleInput.spec_version || '2.1',
        JSON.stringify(createBundleInput.objects?.map(obj => obj.type) || []),
        Date.now().toString() // Ensure uniqueness
      ].join('|');

      const timestamp = new Date().toISOString();
      const bundle: Bundle = {
        ...createBundleInput,
        id: createBundleInput.id || `bundle--${uuidv5(idSeed, NAMESPACE)}`,
        type: 'bundle',
        spec_version: createBundleInput.spec_version || '2.1',
        created: timestamp,
        modified: timestamp
      };

      // Validate the complete bundle before saving
      this.validateStixBundle(bundle);

      const response = await this.client.index({
        index: this.index,
        id: bundle.id,
        body: bundle,
        refresh: 'wait_for', // Wait for refresh to ensure consistency
      }).catch(error => {
        throw new Error(`OpenSearch error: ${this.safeGetErrorMessage(error)}`);
      });

      if (!['created', 'updated'].includes(response.body?.result)) {
        throw new Error(`Unexpected OpenSearch response: ${JSON.stringify(response.body)}`);
      }

      return bundle;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create bundle',
        details: this.safeGetErrorMessage(error),
        objectId: createBundleInput?.id || 'unknown',
        input: createBundleInput
      });
    }
  }

  private validateBundleInput(input: CreateBundleInput): void {
    if (!input.objects || input.objects.length === 0) {
      throw new Error('Bundle must contain at least one object');
    }

    if (input.spec_version && input.spec_version !== '2.1') {
      throw new Error('Only STIX 2.1 bundles are supported');
    }
  }

  private validateStixBundle(bundle: Bundle): void {
    // Validate all objects in the bundle
    bundle.objects?.forEach(obj => {
      if (!obj.id || !obj.type || !obj.spec_version) {
        throw new Error('Invalid STIX object in bundle - missing required fields');
      }
    });
  }

  private safeGetErrorMessage(error: any): string {
    if (typeof error === 'string') return error;
    if (error?.message) return error.message;
    if (error?.response?.data?.error) return error.response.data.error;
    if (error?.body?.error) return JSON.stringify(error.body.error);
    return 'Unknown error occurred';
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