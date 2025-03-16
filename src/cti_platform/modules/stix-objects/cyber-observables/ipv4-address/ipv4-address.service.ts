import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateIPv4AddressInput, UpdateIPv4AddressInput } from './ipv4-address.input';
import { IPv4Address } from './ipv4-address.entity';
import { SearchIPv4AddressInput } from './ipv4-address.resolver';
@Injectable()
export class IPv4AddressService {
  private readonly index = 'ipv4-addresses'; // OpenSearch index name
  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new IPv4 address document
  async create(createIPv4AddressInput: CreateIPv4AddressInput): Promise<IPv4Address> {
    const id = `ipv4-${Date.now()}`;  // Generate a unique ID for the IPv4 address
    const now = new Date().toISOString();

    // Ensure spec_version, value, and other fields are included
    const doc: IPv4Address = {
      id,
      type: 'ipv4-addr',
      spec_version: '2.1',  // Include spec_version here
      created: now,
      modified: now,
      value: createIPv4AddressInput.value,  // Ensure value is passed from input
      resolves_to_refs: createIPv4AddressInput.resolves_to_refs || [],
      belongs_to_refs: createIPv4AddressInput.belongs_to_refs || [],
      ...createIPv4AddressInput,  // Include other fields from the input
    };

    try {
      // Index the document in OpenSearch
      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: doc,
      });

      // Ensure that the document was successfully created
      if (response.body.result !== 'created') {
        throw new InternalServerErrorException('Failed to create IPv4 address');
      }

      return doc;  // Return the created document
    } catch (error) {
      throw new InternalServerErrorException('Error creating IPv4 address in OpenSearch', error.message);
    }
  }

  // Update an existing IPv4 address document
  async update(id: string, updateIPv4AddressInput: UpdateIPv4AddressInput): Promise<IPv4Address> {
    const now = new Date().toISOString();

    // Fetch the existing IPv4 address document from OpenSearch
    const existingIPv4Address = await this.findOne(id);
    if (!existingIPv4Address) {
      throw new NotFoundException(`IPv4 Address with ID ${id} not found`);
    }

    // Prepare the updated document with the new data
    const updatedDoc = {
      ...existingIPv4Address,
      ...updateIPv4AddressInput,
      resolves_to_refs: updateIPv4AddressInput.resolves_to_refs || existingIPv4Address.resolves_to_refs,
      belongs_to_refs: updateIPv4AddressInput.belongs_to_refs || existingIPv4Address.belongs_to_refs,
      spec_version: existingIPv4Address.spec_version,  // Retain spec_version during update
      modified: new Date().toISOString(),

    };

    try {
      // Update the document in OpenSearch
      await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
      });

      return updatedDoc;  // Return the updated document
    } catch (error) {
      throw new InternalServerErrorException('Error updating IPv4 address in OpenSearch', error.message);
    }
  }

  // Find an IPv4 address by its ID
  async findOne(id: string): Promise<IPv4Address | null> {
    try {
      const response = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      // Return the document source (the actual IPv4 address data)
      return {
        id,
        type: 'ipv4-addr',
        spec_version: response.body._source.spec_version || '2.1',  // Ensure spec_version is included
        created: response.body._source.created || new Date().toISOString(),
        modified: response.body._source.modified || new Date().toISOString(),
        value: response.body._source.value,  // Ensure value is included
        resolves_to_refs: response.body._source.resolves_to_refs || [],
        belongs_to_refs: response.body._source.belongs_to_refs || [],
        ...response.body._source,
      };
    } catch (error) {
      if (error.meta?.body?.found === false) {
        return null;  // Return null if the IPv4 address was not found
      }
      throw new InternalServerErrorException('Error fetching IPv4 address from OpenSearch', error.message);
    }
  }

  // Remove an IPv4 address document by its ID
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });

      return response.body.result === 'deleted';  // Return true if the document was deleted
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`IPv4 Address with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting IPv4 address in OpenSearch', error.message);
    }
  }

  // Find IPv4 addresses by value
  async findByValue(value: string): Promise<IPv4Address[]> {
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
        type: 'ipv4-addr',
        spec_version: hit._source.spec_version || '2.1',  // Ensure spec_version is included
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        value: hit._source.value,  // Ensure value is included
        resolves_to_refs: hit._source.resolves_to_refs || [],
        belongs_to_refs: hit._source.belongs_to_refs || [],
        ...hit._source,
      }));
    } catch (error) {
      throw new InternalServerErrorException('Error fetching IPv4 addresses by value from OpenSearch', error.message);
    }
  }
  async searchWithFilters(
    searchParams: SearchIPv4AddressInput, // Filters passed by the user
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
        type: 'ipv4-addr',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        resolves_to_refs: hit._source.resolves_to_refs || [],
        belongs_to_refs: hit._source.belongs_to_refs || [],
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
      throw new InternalServerErrorException('Error fetching IPv4 addresses from OpenSearch');
    }
  }
  
}
