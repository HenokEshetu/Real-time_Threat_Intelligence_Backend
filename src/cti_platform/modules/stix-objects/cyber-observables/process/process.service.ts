import { Injectable } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateProcessInput, UpdateProcessInput } from './process.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';

import { SearchProcessInput } from './process.resolver';
@Injectable()
export class ProcessService {
  private readonly index = 'process'; // OpenSearch index name

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new Process
  async create(createProcessInput: CreateProcessInput): Promise<any> {
    this.validateProcess(createProcessInput); // Validate input

    const id = `process-${uuidv4()}`; // Generate a unique ID for the document
    const now = new Date().toISOString(); // Set timestamps
    const process = {
      id, // Set the generated ID
      type: 'process',
      spec_version: '2.1',
      created: now,
      modified: now,
      ...createProcessInput, // Spread input data
    };

    try {
      // Index the new process into OpenSearch
      await this.openSearchClient.index({
        index: this.index,
        id,
        body: process,
      });

      return process; // Return the created process object
    } catch (error) {
      throw new StixValidationError(`Error creating process: ${error.message}`);
    }
  }

  
  // Get a single process entry by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      return {
        id, // Return the ID
        type: 'process',
        spec_version: '2.1',
        created: body._source.created || new Date().toISOString(),
        modified: body._source.modified || new Date().toISOString(),
        ...body._source, // Include other fields from the document
      };
    } catch (error) {
      throw new StixValidationError(`Process with ID ${id} not found`);
    }
  }

  // Update an existing process
  async update(id: string, updateProcessInput: UpdateProcessInput): Promise<any> {
    this.validateProcess(updateProcessInput); // Validate input

    try {
      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: {
          doc: updateProcessInput, // Update the specified fields
        },
      });

      if (response.body.result !== 'updated') {
        throw new StixValidationError('Error updating process');
      }

      return { id, ...updateProcessInput }; // Return the updated process
    } catch (error) {
      throw new StixValidationError(`Error updating process: ${error.message}`);
    }
  }

  // Remove a process entry by ID
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });

      return response.body.result === 'deleted'; // Return true if successfully deleted
    } catch (error) {
      throw new StixValidationError(`Error deleting process with ID ${id}`);
    }
  }

  // Validate the process input
  private validateProcess(input: CreateProcessInput | UpdateProcessInput): void {
    // Validate PID is a positive integer
    if (input.pid !== undefined && (input.pid < 0 || !Number.isInteger(input.pid))) {
      throw new StixValidationError('Process ID must be a positive integer');
    }

    // Validate created_time is a valid timestamp
    if (input.created_time) {
      const timestamp = new Date(input.created_time);
      if (isNaN(timestamp.getTime())) {
        throw new StixValidationError('Created time must be a valid timestamp');
      }
    }

    // Validate environment variables format
    if (input.environment_variables) {
      for (const envVar of input.environment_variables) {
        if (typeof envVar !== 'string') {
          throw new StixValidationError('Environment variables must be strings');
        }
      }
    }

    // Validate references are in STIX format
    const validateStixRef = (ref: string) => {
      if (!ref.match(/^[a-z0-9-]+--[0-9a-fA-F-]{36}$/)) {
        throw new StixValidationError(`Invalid STIX reference format: ${ref}`);
      }
    };

    if (input.creator_user_ref) {
      validateStixRef(input.creator_user_ref);
    }

    if (input.image_ref) {
      validateStixRef(input.image_ref);
    }

    if (input.parent_ref) {
      validateStixRef(input.parent_ref);
    }

    if (input.child_refs) {
      input.child_refs.forEach(validateStixRef);
    }

    if (input.opened_connection_refs) {
      input.opened_connection_refs.forEach(validateStixRef);
    }
  }

// Search Processes with filters
async searchWithFilters(
  from: number = 0,
  size: number = 10,
  filters: SearchProcessInput
): Promise<any[]> {
  try {
    const mustClauses: any[] = [];

    Object.entries(filters).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        if (Array.isArray(value)) {
          mustClauses.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          mustClauses.push({ term: { [key]: value } });
        } else {
          mustClauses.push({ match: { [key]: value } });
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
      type: 'process',
      spec_version: '2.1',
      created: hit._source.created || new Date().toISOString(),
      modified: hit._source.modified || new Date().toISOString(),
      ...hit._source,
    }));
  } catch (error) {
    throw new StixValidationError(`Error searching processes: ${error.message}`);
  }
}




}
