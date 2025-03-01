import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateUrlInput, UpdateUrlInput } from './url.input';
import { Url } from './url.entity';
import { v4 as uuidv4 } from 'uuid';
import { SearchUrlInput } from './url.resolver';

@Injectable()
export class UrlService {
  private readonly index = 'urls';

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createUrlInput: CreateUrlInput): Promise<Url> {
    const id = `url--${uuidv4()}`;
    const now = new Date().toISOString();

    const doc: Url = {
      id,
      type: 'url',
      spec_version: '2.1',
      created: new Date().toISOString(),

      modified: new Date().toISOString(),

      value: createUrlInput.value,
    };

    const response = await this.openSearchClient.index({
      index: this.index,
      id,
      body: doc,
    });

    if (response.body.result !== 'created') {
      throw new InternalServerErrorException('Failed to create URL');
    }

    return doc;
  }

  async findOne(id: string): Promise<Url> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      return response.body._source as Url;
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`URL with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching URL from OpenSearch');
    }
  }

  async update(id: string, updateUrlInput: UpdateUrlInput): Promise<Url> {
    const url = await this.findOne(id);
    if (!url) throw new NotFoundException(`URL with ID ${id} not found`);

    const modified = new Date().toISOString()

    const updatedDoc = { ...url, ...updateUrlInput, modified };

    const response = await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updatedDoc },
    });

    if (response.body.result !== 'updated') {
      throw new InternalServerErrorException('Failed to update URL');
    }

    return updatedDoc;
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({ index: this.index, id });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`URL with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting URL from OpenSearch');
    }
  }

  /**
   * Perform dynamic search with filters
   */
  async searchWithFilters(
    searchParams: SearchUrlInput,
    page: number = 1,
    pageSize: number = 10
  ): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];

      // Construct dynamic search query based on provided filters
      for (const [key, value] of Object.entries(searchParams)) {
        if (value !== undefined) {
          if (value instanceof Date) {
            mustQueries.push({ range: { [key]: { gte: value.toISOString() } } });
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

      // Map results to the required structure
      const results = body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'url',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        ...hit._source,
      }));

      // Return results with pagination metadata
      return {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results,
      };
    } catch (error) {
      throw new InternalServerErrorException('Error searching URLs in OpenSearch');
    }
  }
}
