import { Injectable } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateMutexInput, UpdateMutexInput } from './mutex.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchMutexInput } from './mutex.resolver';
@Injectable()
export class MutexService {
  private readonly index = 'mutexes'; // Define OpenSearch index for mutexes

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new Mutex
  async create(createMutexInput: CreateMutexInput): Promise<any> {
    try {
      const id = `mutex-${uuidv4()}`; // Generate a unique ID for the mutex
      const now = new Date().toISOString(); // Set timestamps
      const mutex = {
        id, // Set the generated ID
        type: 'mutex',
        spec_version: '2.1',
        created: now,
        modified: now,
        ...createMutexInput, // Spread input data
      };

      // Index the new mutex into OpenSearch
      await this.openSearchClient.index({
        index: this.index,
        id,
        body: mutex,
      });

      return mutex; // Return the created mutex
    } catch (error) {
      throw new StixValidationError(`Error creating mutex: ${error.message}`);
    }
  }

  

  // Get a single Mutex by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      return {
        id, // Return the ID
        type: 'mutex',
        spec_version: '2.1',
        created: body._source.created || new Date().toISOString(),
        modified: body._source.modified || new Date().toISOString(),
        ...body._source, // Include other fields from the document
      };
    } catch (error) {
      throw new StixValidationError(`Mutex with ID ${id} not found`);
    }
  }

  // Update an existing Mutex
  async update(id: string, updateMutexInput: UpdateMutexInput): Promise<any> {
    try {
      const mutex = await this.findOne(id); // Fetch the current mutex data
      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: {
          doc: updateMutexInput, // Update the specified fields
        },
      });

      if (response.body.result !== 'updated') {
        throw new StixValidationError('Error updating mutex');
      }

      return { ...mutex, ...updateMutexInput }; // Return the updated mutex data
    } catch (error) {
      throw new StixValidationError(`Error updating mutex: ${error.message}`);
    }
  }

  // Remove a Mutex by ID
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });

      return response.body.result === 'deleted'; // Return true if successfully deleted
    } catch (error) {
      throw new StixValidationError(`Error deleting mutex with ID ${id}`);
    }
  }

  // Find Mutexes by name
  async findByName(name: string): Promise<any[]> {
    try {
      const { body } = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: {
            match: {
              name: name,
            },
          },
        },
      });

      return body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'mutex',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        ...hit._source,
      }));
    } catch (error) {
      throw new StixValidationError(`Error fetching mutexes with name ${name}`);
    }
  }


  async searchWithFilters(from: number = 0, size: number = 10, filters: SearchMutexInput): Promise<any[]> {
    try {
      const mustClauses: any[] = [];
  
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          if (Array.isArray(value)) {
            mustClauses.push({ terms: { [key]: value } }); // Use 'terms' for arrays
          } else if (typeof value === 'boolean' || typeof value === 'number') {
            mustClauses.push({ term: { [key]: value } }); // Use 'term' for exact matches on numbers/booleans
          } else {
            mustClauses.push({ match: { [key]: value } }); // Use 'match' for text-based search
          }
        }
      });
  
      const query = mustClauses.length > 0 ? { bool: { must: mustClauses } } : { match_all: {} };
  
      const { body } = await this.openSearchClient.search({
        index: this.index,
        body: {
          query,
        },
        from,
        size,
      });
  
      return body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'mutex',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        ...hit._source,
      }));
    } catch (error) {
      throw new StixValidationError(`Error searching mutexes: ${error.message}`);
    }
  }
  



  
}
