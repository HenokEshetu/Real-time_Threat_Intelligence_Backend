import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateAutonomousSystemInput, UpdateAutonomousSystemInput } from './autonomous-system.input';
import { AutonomousSystem } from './autonomous-system.entity';
import { SearchAutonomousSystemInput } from './autonomous-system.resolver';
@Injectable()
export class AutonomousSystemService {
  private readonly index = 'autonomous-systems';
  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }
  async searchWithFilters(
    searchParams: SearchAutonomousSystemInput,
    from: number = 0,
    size: number = 10
  ): Promise<any> {
    try {
      const mustQueries = [];
  
      // Construct dynamic search query
      for (const [key, value] of Object.entries(searchParams)) {
        if (value !== undefined) {
          if (typeof value === 'number') {
            mustQueries.push({ term: { [key]: value } }); // Exact match for numbers
          } else {
            mustQueries.push({ match: { [key]: value } }); // Full-text search for strings
          }
        }
      }
  
      // Use match_all if no filters are provided
      const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };
  
      // Execute search query in OpenSearch
      const { body } = await this.openSearchClient.search({
        index: this.index,
        from,
        size,
        body: { query },
      });
  
      // Extract total count of records
      const total = body.hits.total instanceof Object ? body.hits.total.value : body.hits.total;
  
      // Map results to required format
      const results = body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'autonomous-system',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        ...hit._source,
      }));
  
      // Return results with pagination details
      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results,
      };
    } catch (error) {
      throw new InternalServerErrorException('Error fetching Autonomous Systems from OpenSearch');
    }
  }
  
  
  async create(createAutonomousSystemInput: CreateAutonomousSystemInput): Promise<AutonomousSystem> {
    const id = `as-${createAutonomousSystemInput.number}`;
    const now = new Date().toISOString(); // Set timestamps

    const doc: AutonomousSystem = {
      id,
      type: 'autonomous-system',
      spec_version: '2.1',
      created: now,
      modified: now,
      ...createAutonomousSystemInput,
    };

    const response = await this.openSearchClient.index({
      index: this.index,
      id,
      body: doc,
    });

    if (response.body.result !== 'created') {
      throw new InternalServerErrorException('Failed to create Autonomous System');
    }

    return doc;
  }

  async update(id: string, updateAutonomousSystemInput: UpdateAutonomousSystemInput): Promise<AutonomousSystem> {
    const doc = await this.findOne(id);
    if (!doc) throw new NotFoundException(`Autonomous System with ID ${id} not found`);

    const response = await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updateAutonomousSystemInput },
    });

    if (!response.body.result || response.body.result !== 'updated') {
      throw new InternalServerErrorException('Failed to update Autonomous System');
    }

    return { ...doc, ...updateAutonomousSystemInput };
  }

  async findOne(id: string): Promise<AutonomousSystem> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;

      return {
        id,
        type: 'autonomous-system',
        spec_version: '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        ...source,
      };
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`Autonomous System with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching data from OpenSearch');
    }
  }

  async findByNumber(number: number): Promise<AutonomousSystem> {
    const response = await this.openSearchClient.search({
      index: this.index,
      body: {
        query: { match: { number } },
      },
    });

    if (!response.body.hits.hits.length) {
      throw new NotFoundException(`Autonomous System with number ${number} not found`);
    }

    const hit = response.body.hits.hits[0];

    return {
      id: hit._id,
      type: 'autonomous-system',
      spec_version: '2.1',
      created: hit._source.created || new Date().toISOString(),
      modified: hit._source.modified || new Date().toISOString(),
      ...hit._source,
    };
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({ index: this.index, id });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`Autonomous System with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting data from OpenSearch');
    }
  }
}
