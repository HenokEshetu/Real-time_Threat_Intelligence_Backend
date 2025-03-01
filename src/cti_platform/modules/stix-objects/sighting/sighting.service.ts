import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { v4 as uuidv4 } from 'uuid';
import { CreateSightingInput, UpdateSightingInput } from './sighting.input';
import { StixValidationError } from '../../../core/exception/custom-exceptions';
import { SearchSightingInput } from './sighting.resolver';

@Injectable()
export class SightingService {
  private readonly index = 'sightings'; // OpenSearch index name

  private openSearchService: Client;
  

  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new sighting
  async create(createSightingInput: CreateSightingInput): Promise<any> {
    this.validateSighting(createSightingInput);

    const sighting = {
      id: `sighting--${uuidv4()}`,
      type: 'sighting',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createSightingInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: sighting.id,
        body: sighting,
        refresh: 'wait_for',
      });

      return sighting;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create sighting: ${error.message}`);
    }
  }

  //  Find a single sighting by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Sighting with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching sighting: ${error.message}`);
    }
  }

  // Update a sighting
  async update(id: string, updateSightingInput: UpdateSightingInput): Promise<any> {
    try {
      const existingSighting = await this.findOne(id);
      if (!existingSighting) throw new NotFoundException(`Sighting with ID ${id} not found`);

      const updatedSighting = {
        ...existingSighting,
        ...updateSightingInput,
        modified: new Date().toISOString(),
      };

      this.validateSighting(updatedSighting);

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedSighting,
        refresh: 'wait_for',
      });

      return updatedSighting;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update sighting: ${error.message}`);
    }
  }

  //  Delete a sighting
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
        throw new NotFoundException(`Sighting with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete sighting: ${error.message}`);
    }
  }

  //  Advanced search with filters
  async searchSightingWithFilters(filters: SearchSightingInput, page = 1, pageSize = 10): Promise<any> {
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
        } else if (['first_seen', 'last_seen'].includes(key)) {
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
      throw new InternalServerErrorException(`Error searching sightings in OpenSearch: ${error.message}`);
    }
  }

  //  Validate sighting data
  private validateSighting(input: CreateSightingInput | UpdateSightingInput & { first_seen?: Date; last_seen?: Date }): void {
    if (input.first_seen && input.last_seen) {
      if (input.first_seen > input.last_seen) {
        throw new StixValidationError('first_seen must be earlier than or equal to last_seen');
      }
    }

    if (input.count !== undefined && input.count < 0) {
      throw new StixValidationError('count must be a non-negative integer');
    }

    if (input instanceof CreateSightingInput) {
      this.validateStixReference(input.sighting_of_ref, 'sighting_of_ref');
    }

    if (input.observed_data_refs) {
      input.observed_data_refs.forEach((ref) => this.validateStixReference(ref, 'observed_data_refs'));
    }

    if (input.where_sighted_refs) {
      input.where_sighted_refs.forEach((ref) => this.validateStixReference(ref, 'where_sighted_refs'));
    }
  }

  //  Validate STIX ID format
  private validateStixReference(ref: string, fieldName: string): void {
    const stixIdPattern = /^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

    if (!stixIdPattern.test(ref)) {
      throw new StixValidationError(`Invalid STIX reference format in ${fieldName}: ${ref}`);
    }
  }
}
