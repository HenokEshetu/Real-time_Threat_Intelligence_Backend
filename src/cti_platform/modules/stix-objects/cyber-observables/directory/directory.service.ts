import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { Directory } from './directory.entity';
import { CreateDirectoryInput, UpdateDirectoryInput } from './directory.input';
import { SearchDirectoryInput } from './directory.resolver';

@Injectable()
export class DirectoryService {
  private readonly index = 'directories';
  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createDirectoryInput: CreateDirectoryInput): Promise<Directory> {
    const id = `dir-${Date.now()}`;
    const now = new Date().toISOString();

    const doc: Directory = {
      id,
      type: 'directory',
      spec_version: '2.1',
      created: now,
      modified: now,
      path: createDirectoryInput.path, // Ensure `path` is included
      ...createDirectoryInput,
    };

    const response = await this.openSearchClient.index({
      index: this.index,
      id,
      body: doc,
    });

    if (response.body.result !== 'created') {
      throw new InternalServerErrorException('Failed to create directory');
    }

    return doc;
  }

  async update(id: string, updateDirectoryInput: UpdateDirectoryInput): Promise<Directory> {
    const now = new Date().toISOString();
    const existingDirectory = await this.findOne(id);

    if (!existingDirectory) {
      throw new NotFoundException(`Directory with ID ${id} not found`);
    }

    const updatedDoc = {
      ...existingDirectory,
      ...updateDirectoryInput,
      modified: new Date().toISOString(),

    };

    await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updatedDoc },
    });

    return updatedDoc;
  }

  async findOne(id: string): Promise<Directory> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;

      return {
        id,
        type: 'directory',
        spec_version: '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        path: source.path, // Ensure path is included
        ...source,
      };
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`Directory with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching data from OpenSearch');
    }
  }

  async findByPath(path: string): Promise<Directory[]> {
    const response = await this.openSearchClient.search({
      index: this.index,
      body: {
        query: { match: { path } },
      },
    });

    return response.body.hits.hits.map((hit) => ({
      id: hit._id,
      type: 'directory',
      spec_version: '2.1',
      created: hit._source.created || new Date().toISOString(),
      modified: hit._source.modified || new Date().toISOString(),
      path: hit._source.path, // Ensure path is included
      ...hit._source,
    }));
  }

  async searchWithFilters(
    searchParams: SearchDirectoryInput, // Filters passed by the user
    page: number = 1,
    pageSize: number = 10
  ): Promise<any> {
    try {
      // Calculate 'from' for pagination (skip previous pages)
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
            // Otherwise, use match query for the filter
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
  
      // Extract the total number of hits
      const total = body.hits.total instanceof Object ? body.hits.total.value : body.hits.total;
  
      // Map the results to the desired format
      const results = body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'directory',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        ...hit._source,
      }));
  
      // Return results with pagination details
      return {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results,
      };
    } catch (error) {
      throw new InternalServerErrorException('Error fetching directories from OpenSearch');
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
        throw new NotFoundException(`Directory with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting data from OpenSearch');
    }
  }
}
