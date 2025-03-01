import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateNetworkTrafficInput, UpdateNetworkTrafficInput } from './network-traffic.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchNetworkTrafficInput } from './network-traffic.resolver';
@Injectable()
export class NetworkTrafficService {
  private readonly index = 'network-traffic'; // OpenSearch index name

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new NetworkTraffic
  async create(createNetworkTrafficInput: CreateNetworkTrafficInput): Promise<any> {
    this.validateNetworkTraffic(createNetworkTrafficInput); // Validate input

    const id = `network-traffic-${uuidv4()}`; // Generate unique ID for the document
    const now = new Date().toISOString(); // Set timestamps
    const networkTraffic = {
      id, // Set the generated ID
      type: 'network-traffic',
      spec_version: '2.1',
      created: now,
      modified: now,
      ...createNetworkTrafficInput, // Spread input data
    };

    try {
      // Index the new network traffic into OpenSearch
      await this.openSearchClient.index({
        index: this.index,
        id,
        body: networkTraffic,
      });

      return networkTraffic; // Return the created network traffic object
    } catch (error) {
      throw new StixValidationError(`Error creating network traffic: ${error.message}`);
    }
  }

  
  // Get a single NetworkTraffic entry by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      return {
        id, // Return the ID
        type: 'network-traffic',
        spec_version: '2.1',
        created: body._source.created || new Date().toISOString(),
        modified: body._source.modified || new Date().toISOString(),
        ...body._source, // Include other fields from the document
      };
    } catch (error) {
      throw new StixValidationError(`Network traffic with ID ${id} not found`);
    }
  }

  // Update an existing NetworkTraffic
  async update(id: string, updateNetworkTrafficInput: UpdateNetworkTrafficInput): Promise<any> {
    this.validateNetworkTraffic(updateNetworkTrafficInput); // Validate input

    try {
      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: {
          doc: updateNetworkTrafficInput, // Update the specified fields
        },
      });

      if (response.body.result !== 'updated') {
        throw new StixValidationError('Error updating network traffic');
      }

      return { id, ...updateNetworkTrafficInput }; // Return the updated network traffic
    } catch (error) {
      throw new StixValidationError(`Error updating network traffic: ${error.message}`);
    }
  }

  // Remove a NetworkTraffic entry by ID
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });

      return response.body.result === 'deleted'; // Return true if successfully deleted
    } catch (error) {
      throw new StixValidationError(`Error deleting network traffic with ID ${id}`);
    }
  }

  // Validate the network traffic input
  private validateNetworkTraffic(input: CreateNetworkTrafficInput | UpdateNetworkTrafficInput): void {
    // Validate protocols array if provided
    if (input.protocols) {
      if (!Array.isArray(input.protocols)) {
        throw new StixValidationError('Protocols must be an array of strings');
      }

      // Check if all protocols are strings and follow required format
      for (const protocol of input.protocols) {
        if (typeof protocol !== 'string') {
          throw new StixValidationError('All protocols must be strings');
        }

        // Protocol should be lowercase
        if (protocol !== protocol.toLowerCase()) {
          throw new StixValidationError('Protocols must be lowercase');
        }
      }
    }

    // Validate port numbers
    if (input.src_port !== undefined && (input.src_port < 0 || input.src_port > 65535)) {
      throw new StixValidationError('Source port must be between 0 and 65535');
    }
    if (input.dst_port !== undefined && (input.dst_port < 0 || input.dst_port > 65535)) {
      throw new StixValidationError('Destination port must be between 0 and 65535');
    }

    // Validate byte counts and packet counts are non-negative
    if (input.src_byte_count !== undefined && input.src_byte_count < 0) {
      throw new StixValidationError('Source byte count must be non-negative');
    }
    if (input.dst_byte_count !== undefined && input.dst_byte_count < 0) {
      throw new StixValidationError('Destination byte count must be non-negative');
    }
    if (input.src_packets !== undefined && input.src_packets < 0) {
      throw new StixValidationError('Source packets must be non-negative');
    }
    if (input.dst_packets !== undefined && input.dst_packets < 0) {
      throw new StixValidationError('Destination packets must be non-negative');
    }

    // Validate timestamps
    if (input.start && input.end) {
      const startDate = new Date(input.start);
      const endDate = new Date(input.end);
      if (startDate > endDate) {
        throw new StixValidationError('Start time must be before end time');
      }
    }
  }

// Search NetworkTraffic with filters
async searchWithFilters(
  from: number = 0,
  size: number = 10,
  filters: SearchNetworkTrafficInput
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
      type: 'network-traffic',
      spec_version: '2.1',
      created: hit._source.created || new Date().toISOString(),
      modified: hit._source.modified || new Date().toISOString(),
      ...hit._source,
    }));
  } catch (error) {
    throw new StixValidationError(`Error searching network traffic: ${error.message}`);
  }
}


}
