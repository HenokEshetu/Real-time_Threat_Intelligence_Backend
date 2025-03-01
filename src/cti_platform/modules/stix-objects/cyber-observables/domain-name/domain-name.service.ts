import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { DomainName } from './domain-name.entity';
import { CreateDomainNameInput, UpdateDomainNameInput } from './domain-name.input';
import { SearchDomainNameInput } from './domain-name.resolver';
@Injectable()
export class DomainNameService {
  private readonly index = 'domain-names';

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createDomainNameInput: CreateDomainNameInput): Promise<DomainName> {
    const id = `domain-${Date.now()}`;
    const now = new Date().toISOString();

    const doc: DomainName = {
      id,
      type: 'domain-name',
      spec_version: '2.1',
      created: now,
      modified: now,
      value: createDomainNameInput.value, // Ensure `value` exists
      ...createDomainNameInput,
    };

    const response = await this.openSearchClient.index({
      index: this.index,
      id,
      body: doc,
    });

    if (response.body.result !== 'created') {
      throw new InternalServerErrorException('Failed to create domain name');
    }

    return doc;
  }

  async update(id: string, updateDomainNameInput: UpdateDomainNameInput): Promise<DomainName> {
    const now = new Date().toISOString();
    const existingDomain = await this.findOne(id);

    if (!existingDomain) {
      throw new NotFoundException(`DomainName with ID ${id} not found`);
    }

    const updatedDoc = {
      ...existingDomain,
      ...updateDomainNameInput,
      modified: new Date().toISOString(),

    };

    await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updatedDoc },
    });

    return updatedDoc;
  }

  async findOne(id: string): Promise<DomainName> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;

      return {
        id,
        type: 'domain-name',
        spec_version: '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        value: source.value, // Ensure `value` exists
        ...source,
      };
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`DomainName with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching data from OpenSearch');
    }
  }

  async findByValue(value: string): Promise<DomainName[]> {
    const response = await this.openSearchClient.search({
      index: this.index,
      body: {
        query: { match: { value } },
      },
    });

    return response.body.hits.hits.map((hit) => ({
      id: hit._id,
      type: 'domain-name',
      spec_version: '2.1',
      created: hit._source.created || new Date().toISOString(),
      modified: hit._source.modified || new Date().toISOString(),
      value: hit._source.value, // Ensure `value` exists
      ...hit._source,
    }));
  }

  // Get domain name documents based on filters and pagination
async searchWithFilters(
  filters: SearchDomainNameInput, // Filters should be passed
  page: number = 1,
  pageSize: number = 10
): Promise<any> {
  try {
    // Calculate the 'from' value for pagination (skip the previous pages)
    const from = (page - 1) * pageSize;

    // Create the 'must' array for filtering
    const mustQueries = [];

    // Iterate over filters to create the query dynamically
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined) {
        if (typeof value === 'string') {
          mustQueries.push({ match: { [key]: value } }); // Match for string filters
        } else if (typeof value === 'number') {
          mustQueries.push({ term: { [key]: value } }); // Term for exact match with numbers
        }
      }
    }

    // Construct the query with dynamic filters or use match_all if no filters
    const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };

    // Query to fetch domain names with filters and pagination
    const { body } = await this.openSearchClient.search({
      index: this.index,
      from, // Skip documents based on the current page
      size: pageSize, // Limit the number of results per page
      body: {
        query,
      },
    });

    // Determine the total number of hits
    const total = body.hits.total instanceof Object ? body.hits.total.value : body.hits.total;

    // Map the results to the desired format
    const results = body.hits.hits.map((hit) => ({
      id: hit._id,
      type: 'domain-name',
      spec_version: '2.1',
      created: hit._source.created || new Date().toISOString(),
      modified: hit._source.modified || new Date().toISOString(),
      value: hit._source.value, // Ensure `value` exists
      ...hit._source,
    }));

    // Return the results with pagination details
    return {
      page,
      pageSize,
      total, // Total number of documents
      totalPages: Math.ceil(total / pageSize), // Calculate total pages
      results,
    };
  } catch (error) {
    throw new InternalServerErrorException('Error fetching domain names from OpenSearch');
  }
}

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`DomainName with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting data from OpenSearch');
    }
  }
}
