import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateProcessInput, UpdateProcessInput } from './process.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchProcessInput } from './process.resolver';
import { Process } from './process.entity';

@Injectable()
export class ProcessService implements OnModuleInit {
  private readonly index = 'process';
  private readonly openSearchClient: Client;

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
    this.openSearchClient = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();}


  async create(createProcessInput: CreateProcessInput): Promise<Process> {
    this.validateProcess(createProcessInput);

    const id = `process-${uuidv4()}`;
    const now = new Date().toISOString();

    const process: Process = {
      ...createProcessInput,
      ...(createProcessInput.enrichment ? { enrichment: createProcessInput.enrichment } : {}),
      id,
      type: 'process' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
      
    };

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: process,
        refresh: 'wait_for', // Ensures the document is available for search immediately
      });

      if (response.body.result !== 'created') {
        throw new InternalServerErrorException('Failed to index process document');
      }

      return process;
    } catch (error) {
      throw new StixValidationError(`Failed to create process: ${error.message}`);
    }
  }

 
  async findOne(id: string): Promise<Process> {
    try {
      const response = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id,
        type: 'process' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Process with ID ${id} not found`);
      }
      throw new InternalServerErrorException(`Failed to fetch process: ${error.message}`);
    }
  }

  
  async update(id: string, updateProcessInput: UpdateProcessInput): Promise<Process> {
    this.validateProcess(updateProcessInput);

    try {
      const existingProcess = await this.findOne(id);
      const updatedDoc: Partial<Process> = {
        ...updateProcessInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3, // Retry on version conflicts
      });

      if (response.body.result !== 'updated') {
        throw new InternalServerErrorException('Failed to update process document');
      }

      return { ...existingProcess, ...updatedDoc };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new StixValidationError(`Failed to update process: ${error.message}`);
    }
  }

 
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException(`Failed to delete process: ${error.message}`);
    }
  }

 
  private validateProcess(input: CreateProcessInput | UpdateProcessInput): void {
    if (input.pid !== undefined && (input.pid < 0 || !Number.isInteger(input.pid))) {
      throw new StixValidationError('Process ID must be a positive integer');
    }

    if (input.created_time) {
      const timestamp = new Date(input.created_time);
      if (isNaN(timestamp.getTime())) {
        throw new StixValidationError('Created time must be a valid timestamp');
      }
    }

    if (input.environment_variables) {
      for (const envVar of input.environment_variables) {
        if (typeof envVar !== 'string') {
          throw new StixValidationError('Environment variables must be strings');
        }
      }
    }

    const validateStixRef = (ref: string) => {
      if (!ref.match(/^[a-z0-9-]+--[0-9a-fA-F-]{36}$/)) {
        throw new StixValidationError(`Invalid STIX reference format: ${ref}`);
      }
    };

    if (input.creator_user_ref) validateStixRef(input.creator_user_ref);
    if (input.image_ref) validateStixRef(input.image_ref);
    if (input.parent_ref) validateStixRef(input.parent_ref);
    if (input.child_refs) input.child_refs.forEach(validateStixRef);
    if (input.opened_connection_refs) input.opened_connection_refs.forEach(validateStixRef);
  }


  async searchWithFilters(
    from: number = 0,
    size: number = 10,
    filters: SearchProcessInput = {},
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Process[];
  }> {
    try {
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      Object.entries(filters).forEach(([key, value]) => {
        if (value === undefined || value === null) return;

        switch (key) {
          case 'pid':
            queryBuilder.query.bool.filter.push({ term: { [key]: value } });
            break;
          case 'created_time':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
              });
            }
            break;
          case 'environment_variables':
            if (Array.isArray(value)) {
              queryBuilder.query.bool.filter.push({ terms: { [key]: value } });
            }
            break;
          case 'creator_user_ref':
          case 'image_ref':
          case 'parent_ref':
            queryBuilder.query.bool.must.push({ match: { [key]: { query: value, lenient: true } } });
            break;
          case 'child_refs':
          case 'opened_connection_refs':
            if (Array.isArray(value)) {
              queryBuilder.query.bool.filter.push({ terms: { [key]: value } });
            }
            break;
          default:
            queryBuilder.query.bool.must.push({ match: { [key]: { query: value, lenient: true } } });
        }
      });

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.openSearchClient.search({
        index: this.index,
        from,
        size,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;

      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results: response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          type: 'process' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException(`Failed to search processes: ${error.message}`);
    }
  }

  /**
   * Ensures the OpenSearch index exists and is properly configured.
   */
  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchClient.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchClient.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                pid: { type: 'integer' },
                created_time: { type: 'date' },
                creator_user_ref: { type: 'keyword' },
                image_ref: { type: 'keyword' },
                parent_ref: { type: 'keyword' },
                child_refs: { type: 'keyword' },
                opened_connection_refs: { type: 'keyword' },
                environment_variables: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException(`Failed to initialize process index: ${error.message}`);
    }
  }
}