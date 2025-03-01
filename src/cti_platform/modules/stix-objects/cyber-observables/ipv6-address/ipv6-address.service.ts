import { Injectable, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateIPv6AddressInput, UpdateIPv6AddressInput } from './ipv6-address.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { IPv6Address } from './ipv6-address.entity';
import { SearchIPv6AddressInput } from './ipv6-address.resolver';
@Injectable()
export class IPv6AddressService {
  private readonly index = 'ipv6-addresses'; // Set your OpenSearch index name here

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new IPv6 address document
  async create(createIPv6AddressInput: CreateIPv6AddressInput): Promise<any> {
    try {
      const id = `ipv6-addr-${createIPv6AddressInput.value}`; // Generate unique ID based on IPv6 address
      const now = new Date().toISOString(); // Set timestamps

      const ipv6Address = {
        id,
        type: 'ipv6-addr',
        spec_version: '2.1',
        created: now,
        modified: now,
        value: createIPv6AddressInput.value,
        resolves_to_refs: createIPv6AddressInput.resolves_to_refs || null, // Nullable field
      };

      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: ipv6Address,
      });

      if (response.body.result !== 'created') {
        throw new InternalServerErrorException('Failed to create IPv6 address');
      }
      
      return ipv6Address;
    } catch (error) {
      throw new StixValidationError(`Error creating IPv6 address: ${error.message}`);
    }
  }


  // Get a specific IPv6 address by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      if (!body.found) {
        throw new NotFoundException(`IPv6 address with ID ${id} not found`);
      }

      return {
        id,
        type: 'ipv6-addr',
        spec_version: '2.1',
        created: body._source.created || new Date().toISOString(),
        modified: body._source.modified || new Date().toISOString(),
        ...body._source,
      };
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`IPv6 address with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching IPv6 address from OpenSearch');
    }
  }

  // Update an existing IPv6 address document
  async update(id: string, updateIPv6AddressInput: UpdateIPv6AddressInput): Promise<any> {
    try {
      // First, fetch the existing document to ensure it exists
      const existingIPv6Address = await this.findOne(id);

      // Prepare the updated document
      const updatedIPv6Address = {
        ...existingIPv6Address,
        ...updateIPv6AddressInput,
        modified: new Date().toISOString(), // Update the modified timestamp
      };

      // Update the document in OpenSearch
      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: {
          doc: updatedIPv6Address,
        },
      });

      if (response.body.result !== 'updated') {
        throw new InternalServerErrorException('Failed to update IPv6 address');
      }

      return updatedIPv6Address;
    } catch (error) {
      throw new StixValidationError(`Error updating IPv6 address: ${error.message}`);
    }
  }

  // Delete an IPv6 address document by ID
  async remove(id: string): Promise<boolean> {
    try {
      const { body } = await this.openSearchClient.delete({
        index: this.index,
        id,
      });

      return body.result === 'deleted';
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`IPv6 address with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting IPv6 address from OpenSearch');
    }
  }

  async searchWithFilters(
    searchParams: SearchIPv6AddressInput, // Filters passed by the user
    page: number = 1,
    pageSize: number = 10
  ): Promise<any> {
    try {
      // Calculate the 'from' value for pagination (skip the previous pages)
      const from = (page - 1) * pageSize;
      const mustQueries = [];
  
      // Construct dynamic search query based on filters (searchParams)
      for (const [key, value] of Object.entries(searchParams)) {
        if (value !== undefined) {
          // If the value is a Date, use range query
          if (value instanceof Date) {
            mustQueries.push({
              range: { [key]: { gte: value.toISOString() } }, // Filters based on a date range (greater than or equal to)
            });
          } else {
            mustQueries.push({ match: { [key]: value } });
          }
        }
      }
  
      // Use match_all if no filters are provided
      const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };
  
      // Execute search query in OpenSearch
      const { body } = await this.openSearchClient.search({
        index: this.index,
        from,
        size: pageSize,
        body: { query },
      });
  
      // Extract total number of hits
      const total = body.hits.total instanceof Object ? body.hits.total.value : body.hits.total;
  
      // Map the results to the desired format
      const results = body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'ipv6-addr',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        ...hit._source,
      }));
  
      // Return results with pagination details
      return {
        page,
        pageSize,
        total, // Total number of documents
        totalPages: Math.ceil(total / pageSize), // Calculate total pages
        results,
      };
    } catch (error) {
      throw new InternalServerErrorException('Error fetching IPv6 addresses from OpenSearch');
    }
  }
  



// Find IPv4 addresses by value
  async findByValue(value: string): Promise<IPv6Address[]> {
    try {
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: {
            match: {
              value: value,  // Search by the value field
            },
          },
        },
      });

      // Return the matched documents
      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'ipv6-addr',
        spec_version: hit._source.spec_version || '2.1',  // Ensure spec_version is included
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        value: hit._source.value,  // Ensure value is included
        ...hit._source,
      }));
    } catch (error) {
      throw new InternalServerErrorException('Error fetching IPv6 addresses by value from OpenSearch', error.message);
    }




  }
  
}










