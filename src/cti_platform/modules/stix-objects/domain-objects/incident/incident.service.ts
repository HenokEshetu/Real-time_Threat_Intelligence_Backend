import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client } from '@opensearch-project/opensearch';
import { CreateIncidentInput, UpdateIncidentInput } from './incident.input';
import { SearchIncidentInput } from './incident.resolver';
@Injectable()
export class IncidentService {
  private readonly index = 'incidents'; // OpenSearch index name

  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create incident
  async create(createIncidentInput: CreateIncidentInput): Promise<any> {
    const incident = {
      id: `incident--${uuidv4()}`,
      type: 'incident',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createIncidentInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: incident.id,
        body: incident,
        refresh: 'wait_for',
      });

      return incident;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create incident: ${error.message}`);
    }
  }

  // Find incident by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Incident with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching incident: ${error.message}`);
    }
  }

  // Update incident
  async update(id: string, updateIncidentInput: UpdateIncidentInput): Promise<any> {
    try {
      const existingIncident = await this.findOne(id);

      const updatedIncident = {
        ...existingIncident,
        ...updateIncidentInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedIncident,
        refresh: 'wait_for',
      });

      return updatedIncident;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update incident: ${error.message}`);
    }
  }

  // Delete incident
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
        throw new NotFoundException(`Incident with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete incident: ${error.message}`);
    }
  }


  // Dynamic Search with Filters  
  async searchIncidentWithFilters(filters: SearchIncidentInput, page = 1, pageSize = 10): Promise<any> {
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
      throw new InternalServerErrorException(`Error searching incidents in OpenSearch: ${error.message}`);
    }
  }
}
