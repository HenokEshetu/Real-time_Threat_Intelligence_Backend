import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { v4 as uuidv4 } from 'uuid';
import { CreateSightingInput, UpdateSightingInput } from './sighting.input';
import { StixValidationError } from '../../../core/exception/custom-exceptions';
import { SearchSightingInput } from './sighting.resolver';
import { Sighting } from './sighting.entity';

@Injectable()
export class SightingService implements OnModuleInit {
  private readonly index = 'sightings';
  private readonly openSearchService: Client;

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
    this.openSearchService = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createSightingInput: CreateSightingInput): Promise<Sighting> {
    this.validateSighting(createSightingInput);

    const sighting: Sighting = {
      ...createSightingInput,
      id: `sighting--${uuidv4()}`,
      type: 'sighting' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      sighting_of_ref: createSightingInput.sighting_of_ref, // Required field
     
    };

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: sighting.id,
        body: sighting,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index sighting');
      }
      return sighting;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create sighting',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<Sighting> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'sighting' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        sighting_of_ref: source.sighting_of_ref, // Required field
        first_seen:source.first_seen,
        last_seen:source.last_seen,
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Sighting with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch sighting',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateSightingInput: UpdateSightingInput): Promise<Sighting> {
    try {
      const existingSighting = await this.findOne(id);
      const updatedSighting: Sighting = {
        ...existingSighting,
        ...updateSightingInput,
        modified: new Date().toISOString(),
      };

      this.validateSighting(updatedSighting);

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedSighting },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update sighting');
      }

      return updatedSighting;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update sighting',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
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
        message: 'Failed to delete sighting',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchSightingInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Sighting[];
  }> {
    try {
      const from = Math.max(0, (page - 1) * pageSize);
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [], should: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          queryBuilder.query.bool.filter.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          queryBuilder.query.bool.filter.push({ term: { [key]: value } });
        } else if (['first_seen', 'last_seen', 'created', 'modified'].includes(key)) {
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

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length && !queryBuilder.query.bool.should.length) {
        queryBuilder.query = { match_all: {} };
      } else if (queryBuilder.query.bool.should.length > 0) {
        queryBuilder.query.bool.minimum_should_match = 1;
      }

      const response = await this.openSearchService.search({
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
          ...hit._source,
          id: hit._id,
          type: 'sighting' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          first_seen:hit._source.first_seen,
          last_seen:hit._source.last_seen,
          sighting_of_ref: hit._source.sighting_of_ref, // Required field
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search sightings',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchService.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchService.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                sighting_of_ref: { type: 'keyword' },
                observed_data_refs: { type: 'keyword' },
                where_sighted_refs: { type: 'keyword' },
                first_seen: { type: 'date' },
                last_seen: { type: 'date' },
                count: { type: 'integer' },
                summary: { type: 'boolean' },
                description: { type: 'text' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize sightings index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateSighting(input: CreateSightingInput | UpdateSightingInput): void {
    // Required field validation
    if (!('sighting_of_ref' in input) || !input.sighting_of_ref) {
      throw new StixValidationError('sighting_of_ref is required');
    }

    // Date validation
    if (input.first_seen && input.last_seen) {
      const firstSeen = input.first_seen instanceof Date ? input.first_seen : new Date(input.first_seen);
      const lastSeen = input.last_seen instanceof Date ? input.last_seen : new Date(input.last_seen);
      if (firstSeen > lastSeen) {
        throw new StixValidationError('first_seen must be earlier than or equal to last_seen');
      }
    }

    // Count validation
    if (input.count !== undefined && (typeof input.count !== 'number' || input.count < 0 || !Number.isInteger(input.count))) {
      throw new StixValidationError('count must be a non-negative integer');
    }

    // STIX reference validation
    this.validateStixReference(input.sighting_of_ref, 'sighting_of_ref');
    
    if (input.observed_data_refs) {
      input.observed_data_refs.forEach((ref) => this.validateStixReference(ref, 'observed_data_refs'));
    }
    
    if (input.where_sighted_refs) {
      input.where_sighted_refs.forEach((ref) => this.validateStixReference(ref, 'where_sighted_refs'));
    }
  }

  private validateStixReference(ref: string, fieldName: string): void {
    const stixIdPattern = /^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!stixIdPattern.test(ref)) {
      throw new StixValidationError(`Invalid STIX reference format in ${fieldName}: ${ref}`);
    }
  }
}