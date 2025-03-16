import { Injectable } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateSoftwareInput, UpdateSoftwareInput } from './software.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { SearchSoftwareInput } from './software.resolver';

@Injectable()
export class SoftwareService {
  private readonly index = 'software'; // OpenSearch index name

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new software record
  async create(createSoftwareInput: CreateSoftwareInput): Promise<any> {
    this.validateSoftware(createSoftwareInput);

    const software = {
      ...createSoftwareInput,
      type: 'software',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
    };

    // Insert software into OpenSearch
    const { body } = await this.openSearchClient.index({
      index: this.index,
      body: software,
    });

    return {
      id: body._id,
      ...software,
    };
  }

  
  // Find one software by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      return {
        id: body._id,
        ...body._source,
      };
    } catch (error) {
      throw new StixValidationError('Software not found');
    }
  }

  // Update an existing software record
  async update(id: string, updateSoftwareInput: UpdateSoftwareInput): Promise<any> {
    this.validateSoftware(updateSoftwareInput);

    const software = {
      ...updateSoftwareInput,
      modified: new Date().toISOString(),
    };

    // Update the software in OpenSearch
    await this.openSearchClient.update({
      index: this.index,
      id,
      body: {
        doc: software,
      },
    });

    return this.findOne(id);
  }

  // Remove a software record by ID
  async remove(id: string): Promise<boolean> {
    const result = await this.openSearchClient.delete({
      index: this.index,
      id,
    });

    return result.body.result === 'deleted';
  }

  // Validate software fields before inserting or updating
  private validateSoftware(input: CreateSoftwareInput | UpdateSoftwareInput): void {
    // Validate name is not empty if provided
    if ('name' in input && (!input.name || input.name.trim().length === 0)) {
      throw new StixValidationError('Software name cannot be empty');
    }

    // Validate CPE format if provided
    if (input.cpe) {
      const cpeRegex = /^cpe:(?:2\.[23]|)\:([aho]):(?:[^:]+)(?::[^:]+){0,5}:(?:[^:]+|)(?::[^:]+|)$/;
      if (!cpeRegex.test(input.cpe)) {
        throw new StixValidationError('Invalid CPE format');
      }
    }

    // Validate SWID format if provided
    if (input.swid) {
      input.swid.forEach((swid) => {
        if (!swid || swid.trim().length === 0) {
          throw new StixValidationError('SWID tags cannot be empty');
        }
      });
    }

    // Validate languages format if provided
    if (input.languages) {
      const languageRegex = /^[a-zA-Z]{2,3}(-[a-zA-Z]{2,3})?$/;
      input.languages.forEach((lang) => {
        if (!languageRegex.test(lang)) {
          throw new StixValidationError(`Invalid language format: ${lang}. Use ISO 639-2 or ISO 639-3 codes.`);
        }
      });
    }

    // Validate version format if provided
    if (input.version) {
      const versionRegex = /^[0-9a-zA-Z.-]+$/;
      if (!versionRegex.test(input.version)) {
        throw new StixValidationError('Invalid version format');
      }
    }

    // Validate vendor if provided
    if (input.vendor && input.vendor.trim().length === 0) {
      throw new StixValidationError('Vendor name cannot be empty');
    }
  }

// Search Software with filters
async searchWithFilters(
  from: number = 0,
  size: number = 10,
  filters: SearchSoftwareInput
): Promise<any[]> {
  try {
    const mustClauses: any[] = [];

    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        if (Array.isArray(value)) {
          mustClauses.push({ terms: { [key]: value } }); // If the field is an array, use `terms`
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          mustClauses.push({ term: { [key]: value } }); // Exact match for boolean/number
        } else {
          mustClauses.push({ match: { [key]: value } }); // Fuzzy search for text fields
        }
      }
    });

    const query = mustClauses.length > 0 ? { bool: { must: mustClauses } } : { match_all: {} };

    const { body } = await this.openSearchClient.search({
      index: this.index,
      body: {
        query,
        from,
        size,
        sort: [{ created: { order: 'desc' } }], // Sorting by creation date (latest first)
      },
    });

    return body.hits.hits.map((hit) => ({
      id: hit._id,
      type: 'software',
      created: hit._source.created || new Date().toISOString(),
      modified: hit._source.modified || new Date().toISOString(),
      ...hit._source,
    }));
  } catch (error) {
    throw new StixValidationError(`Error searching software: ${error.message}`);
  }
}





}
