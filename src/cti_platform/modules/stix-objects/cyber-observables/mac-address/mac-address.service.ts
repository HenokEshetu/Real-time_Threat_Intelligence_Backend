import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateMACAddressInput, UpdateMACAddressInput } from './mac-address.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchMACAddressInput } from './mac-address.resolver';
@Injectable()
export class MACAddressService {
  private readonly index = 'mac-addresses'; // Define the OpenSearch index name

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new MAC address
  async create(createMACAddressInput: CreateMACAddressInput): Promise<any> {
    try {
      const id = `mac-${uuidv4()}`; // Generate a unique ID for the document
      const now = new Date().toISOString(); // Set timestamps
      const macAddress = {
        id, // Set the generated ID
        type: 'mac-addr',
        spec_version: '2.1',
        created: now,
        modified: now,
        ...createMACAddressInput, // Spread input data to include the MAC address
      };

      // Index the new MAC address into OpenSearch
      await this.openSearchClient.index({
        index: this.index,
        id,
        body: macAddress,
      });

      return macAddress; // Return the created document
    } catch (error) {
      throw new StixValidationError(`Error creating MAC address: ${error.message}`);
    }
  }

  
  // Get a single MAC address by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      return {
        id, // Return the ID of the document
        type: 'mac-addr',
        spec_version: '2.1',
        created: body._source.created || new Date().toISOString(),
        modified: body._source.modified || new Date().toISOString(),
        ...body._source, // Include the rest of the document's fields
      };
    } catch (error) {
      throw new StixValidationError(`MAC address with ID ${id} not found`);
    }
  }

  // Update a MAC address by ID
  async update(id: string, updateMACAddressInput: UpdateMACAddressInput): Promise<any> {
    try {
      const macAddress = await this.findOne(id); // Fetch the current MAC address
      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updateMACAddressInput }, // Update only the specified fields
      });

      if (response.body.result !== 'updated') {
        throw new StixValidationError('Error updating MAC address');
      }

      return { ...macAddress, ...updateMACAddressInput }; // Return the updated MAC address
    } catch (error) {
      throw new StixValidationError(`Error updating MAC address: ${error.message}`);
    }
  }

  // Remove a MAC address by ID
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });

      return response.body.result === 'deleted'; // Check if the document was successfully deleted
    } catch (error) {
      throw new StixValidationError(`Error deleting MAC address with ID ${id}`);
    }
  }

  
  
  
  
  
    
  
    // Search MAC addresses with dynamic filters and pagination
    async searchWithFilters(
      from: number = 0,
      size: number = 10,
      filter: SearchMACAddressInput
    ): Promise<any[]> {
      try {
        const mustQueries = [];
  
        // Dynamically add filters based on provided fields
        for (const [key, value] of Object.entries(filter)) {
          if (value !== undefined && value !== null) {
            mustQueries.push({ match: { [key]: value } });
          }
        }
  
        // Build OpenSearch query
        const searchQuery = {
          index: this.index,
          body: {
            query: {
              bool: {
                must: mustQueries.length > 0 ? mustQueries : [{ match_all: {} }],
              },
            },
          },
          from,
          size,
        };
  
        // Perform search
        const { body } = await this.openSearchClient.search(searchQuery);
  
        // Map results
        return body.hits.hits.map((hit) => ({
          id: hit._id,
          type: 'mac-addr',
          spec_version: '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          ...hit._source, // Include all document fields
        }));
      } catch (error) {
        throw new InternalServerErrorException('Error fetching MAC addresses from OpenSearch', error.message);
      }
    }
  }
  


