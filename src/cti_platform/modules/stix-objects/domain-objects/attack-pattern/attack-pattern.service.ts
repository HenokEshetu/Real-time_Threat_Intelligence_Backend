import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client } from '@opensearch-project/opensearch';
import { CreateAttackPatternInput, UpdateAttackPatternInput } from './attack-pattern.input';
import { SearchAttackPatternInput } from './attack-pattern.resolver';
@Injectable()
export class AttackPatternService {
  private readonly index = 'attack-patterns'; // OpenSearch index name
  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }



  // Create attack pattern (OpenSearch equivalent of .save())
  async create(createAttackPatternInput: CreateAttackPatternInput): Promise<any> {
    const attackPattern = {
      id: `attack-pattern--${uuidv4()}`,
      type: 'attack-pattern',
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createAttackPatternInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: attackPattern.id,
        body: attackPattern,
        refresh: 'wait_for', // Ensures data is searchable immediately
      });

      return attackPattern;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create attack pattern: ${error.message}`);
    }
  }

  //  Find attack pattern by ID (OpenSearch equivalent of .findOneBy())
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Attack pattern with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching attack pattern: ${error.message}`);
    }
  }

  // Update attack pattern (OpenSearch equivalent of .update())
  async update(id: string, updateAttackPatternInput: UpdateAttackPatternInput): Promise<any> {
    try {
      // Fetch the existing document
      const existingPattern = await this.findOne(id);

      // Merge updates and update 'modified' timestamp
      const updatedPattern = {
        ...existingPattern,
        ...updateAttackPatternInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedPattern,
        refresh: 'wait_for',
      });

      return updatedPattern;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update attack pattern: ${error.message}`);
    }
  }

  // Delete attack pattern (OpenSearch equivalent of .delete())
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
        throw new NotFoundException(`Attack pattern with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete attack pattern: ${error.message}`);
    }
  }


  async searchWithFilters(filters: SearchAttackPatternInput, page = 1, pageSize = 10): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];
      const shouldQueries = [];
      const filterQueries = [];
  
      //  Construct dynamic search queries
      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;
  
        if (Array.isArray(value)) {
          mustQueries.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          mustQueries.push({ term: { [key]: value } });
        } else if (['created', 'modified'].includes(key)) {
          //  Handle date range filtering
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
  
      //  Construct OpenSearch query
      const query: any = { bool: {} };
  
      if (mustQueries.length > 0) query.bool.must = mustQueries;
      if (shouldQueries.length > 0) query.bool.should = shouldQueries;
      if (filterQueries.length > 0) query.bool.filter = filterQueries;
  
      if (Object.keys(query.bool).length === 0) {
        query.bool.must = [{ match_all: {} }];
      }
  
      //  Execute OpenSearch Query
      const { body } = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: {
          query,
          sort: [{ created: { order: 'desc' } }],
        },
      });
  
      //  Fix: Safely extract `total`
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
      throw new InternalServerErrorException(`Error searching attack patterns in OpenSearch: ${error.message}`);
    }
  }
  



}
