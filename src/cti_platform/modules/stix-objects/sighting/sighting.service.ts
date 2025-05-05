import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { v4 as uuidv4 } from 'uuid';
import { CreateSightingInput, UpdateSightingInput } from './sighting.input';
import { StixValidationError } from '../../../core/exception/custom-exceptions';
import { SearchSightingInput } from './sighting.resolver';
import { Sighting } from './sighting.entity';



import { v5 as uuidv5 } from 'uuid';

// Define the UUID namespace 
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

// Utility function to generate STIX-compliant IDs
const generateStixId = (type: string, value: string): string => {
  return `${type}--${uuidv5(value, NAMESPACE)}`;
};

@Injectable()
export class SightingService implements OnModuleInit {
  private readonly index = 'sightings';
  private readonly openSearchService: Client;
  logger: any;
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
    try {
      this.validateSighting(createSightingInput);

      // Generate a deterministic ID based on the sighting properties
      const idSeed = [
        createSightingInput.sighting_of_ref,
        createSightingInput.first_seen,
        createSightingInput.last_seen,
        Date.now().toString() // Add timestamp to ensure uniqueness
      ].join('|');
      
      const sighting: Sighting = {
        ...createSightingInput,
        id: createSightingInput.id || generateStixId('sighting', idSeed),
        type: 'sighting',
        spec_version: '2.1',
        created: new Date().toISOString(),
        modified: new Date().toISOString(),
        sighting_of_ref: createSightingInput.sighting_of_ref,
        first_seen: new Date(createSightingInput.first_seen).toISOString(),
        last_seen: new Date(createSightingInput.last_seen).toISOString(),
      };

      const response = await this.openSearchService.index({
        index: this.index,
        id: sighting.id,
        body: sighting,
        refresh: 'wait_for',
      }).catch(error => {
        throw new Error(`OpenSearch error: ${this.safeGetErrorMessage(error)}`);
      });

      if (!['created', 'updated'].includes(response.body?.result)) {
        throw new Error(`Unexpected OpenSearch response: ${JSON.stringify(response.body)}`);
      }

      return sighting;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create sighting',
        details: this.safeGetErrorMessage(error),
        objectId: createSightingInput?.id || 'unknown',
        input: createSightingInput
      });
    }
  }


private safeGetErrorMessage(error: any): string {
  if (typeof error === 'string') return error;
  if (error?.message) return error.message;
  if (error?.response?.data?.error) return error.response.data.error;
  if (error?.body?.error) return JSON.stringify(error.body.error);
  return 'Unknown error occurred';
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
        sighting_of_ref: source.sighting_of_ref, 
        first_seen: source.first_seen,
        last_seen: source.last_seen,
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
        // Convert first_seen from string input to a Date
        first_seen: new Date(updateSightingInput.first_seen).toISOString(),
            last_seen: new Date(updateSightingInput.last_seen).toISOString(),
      };

      this.validateSighting({
        ...updatedSighting,
        spec_version: '2.1', 
        first_seen: updatedSighting.first_seen,
        last_seen: updatedSighting.last_seen,
      });

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
          first_seen: hit._source.first_seen,
          last_seen: hit._source.last_seen,
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
    try {
      if (!input.sighting_of_ref) {
        throw new StixValidationError('sighting_of_ref is required');
      }

      // Validate STIX reference format
      this.validateStixReference(input.sighting_of_ref, 'sighting_of_ref');

      // Validate dates
      if (input.first_seen && input.last_seen) {
        const firstSeen = new Date(input.first_seen);
        const lastSeen = new Date(input.last_seen);
        
        if (isNaN(firstSeen.getTime()) ){
          throw new StixValidationError('Invalid first_seen date format');
        }
        if (isNaN(lastSeen.getTime())) {
          throw new StixValidationError('Invalid last_seen date format');
        }
        if (firstSeen > lastSeen) {
          throw new StixValidationError('first_seen must be earlier than or equal to last_seen');
        }
      }

      // Validate count
      if (input.count !== undefined) {
        if (typeof input.count !== 'number' || input.count < 0 || !Number.isInteger(input.count)) {
          throw new StixValidationError('count must be a non-negative integer');
        }
      }

      // Validate reference arrays
      this.validateReferenceArray(input.observed_data_refs, 'observed_data_refs');
      this.validateReferenceArray(input.where_sighted_refs, 'where_sighted_refs');

    } catch (error) {
      if (error instanceof StixValidationError) {
        throw error;
      }
      throw new StixValidationError(`Validation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private validateReferenceArray(refs: string[] | undefined, fieldName: string): void {
    if (!refs) return;
    
    refs.forEach((ref, index) => {
      try {
        this.validateStixReference(ref, `${fieldName}[${index}]`);
      } catch (error) {
        throw new StixValidationError(`Invalid reference in ${fieldName} at position ${index}: ${error.message}`);
      }
    });
  }

  

  private validateStixReference(ref: string, fieldName: string): void {
    // More permissive STIX ID pattern that accepts all valid STIX objects
    const stixIdPattern = /^([a-z][a-z0-9-]*)--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    
    if (!ref) {
      throw new StixValidationError(`Empty reference in ${fieldName}`);
    }

    if (!stixIdPattern.test(ref)) {
      throw new StixValidationError(`Invalid STIX reference format in ${fieldName}: ${ref}`);
    }

    // Additional type validation can be added here if needed
  }

}