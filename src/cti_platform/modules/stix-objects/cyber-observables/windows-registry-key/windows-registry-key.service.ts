import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client } from '@opensearch-project/opensearch';
import { CreateWindowsRegistryKeyInput, UpdateWindowsRegistryKeyInput } from './windows-registry-key.input';
import { WindowsRegistryKey } from './windows-registry-key.entity';

import { SearchWindowsRegistryKeyInput } from './windows-registry-key.resolver';

@Injectable()
export class WindowsRegistryKeyService {
  private readonly index = 'windows-registry-keys'; // OpenSearch index name
  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  /**
   * Create a new Windows Registry Key in OpenSearch
   */
  async create(createWindowsRegistryKeyInput: CreateWindowsRegistryKeyInput): Promise<WindowsRegistryKey> {
    const windowsRegistryKey: WindowsRegistryKey = {
      id: `windows-registry-key--${uuidv4()}`,
      ...createWindowsRegistryKeyInput,
      created: new Date().toISOString(),

      modified: new Date().toISOString(),

    };

    await this.openSearchClient.index({
      index: this.index,
      id: windowsRegistryKey.id,
      body: windowsRegistryKey,
    });

    return windowsRegistryKey;
  }

  /**
   * Find one Windows Registry Key by ID
   */
  async findOne(id: string): Promise<WindowsRegistryKey | null> {
    try {
      const { body } = await this.openSearchClient.get({ index: this.index, id });
      return body._source as WindowsRegistryKey;
    } catch (error) {
      throw new NotFoundException('Windows Registry Key not found');
    }
  }

  /**
   * Update a Windows Registry Key in OpenSearch
   */
  async update(id: string, updateWindowsRegistryKeyInput: UpdateWindowsRegistryKeyInput): Promise<WindowsRegistryKey | null> {
    const existingRegistryKey = await this.findOne(id);
    if (!existingRegistryKey) {
      throw new NotFoundException('Windows Registry Key not found');
    }

    const updatedRegistryKey: WindowsRegistryKey = {
      ...existingRegistryKey,
      ...updateWindowsRegistryKeyInput,
      modified: new Date().toISOString(),

    };

    await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updatedRegistryKey },
    });

    return updatedRegistryKey;
  }

  /**
   * Delete a Windows Registry Key from OpenSearch
   */
  async remove(id: string): Promise<boolean> {
    try {
      await this.openSearchClient.delete({ index: this.index, id });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Search Windows Registry Keys with dynamic filters
   */
  async searchWithFilters(
    searchParams: SearchWindowsRegistryKeyInput,
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
        type: 'windows-registry-key',
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
      throw new InternalServerErrorException('Error searching Windows Registry Keys in OpenSearch');
    }
  }
}
