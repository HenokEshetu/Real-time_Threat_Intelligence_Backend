import { Injectable, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { Bundle } from './bundle.entity';
import { CreateBundleInput, UpdateBundleInput } from './bundle.input';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class BundleService {
  private client: Client;
  private readonly index = 'bundles'; // OpenSearch index

  constructor() {
    this.client = new Client({
      node: 'http://localhost:9200',
    });
  }

  /**
   * Create a new STIX Bundle
   */
  async create(createBundleInput: CreateBundleInput): Promise<Bundle> {
    const id = `bundle--${uuidv4()}`;
    const bundle: Bundle = {
      id,
      type: 'bundle',
      ...createBundleInput,
    };

    try {
      await this.client.index({
        index: this.index,
        id,
        body: bundle,
      });

      return bundle;
    } catch (error) {
      throw new InternalServerErrorException('Error creating bundle in OpenSearch');
    }
  }

  /**
   * Find a bundle by ID
   */
  async findOne(id: string): Promise<Bundle> {
    try {
      const { body } = await this.client.get({
        index: this.index,
        id,
      });

      return body._source as Bundle;
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`Bundle with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching bundle from OpenSearch');
    }
  }

  /**
   * Search bundles with filters and pagination
   */
  async searchWithFilters(
    filters: Partial<Bundle>,
    page: number = 1,
    pageSize: number = 10
  ): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];

      // Construct dynamic query based on filters
      for (const [key, value] of Object.entries(filters)) {
        if (value) {
          if (typeof value === 'string') {
            mustQueries.push({
              wildcard: {
                [key]: `*${value}*`, // Partial match
              },
            });
          } else {
            mustQueries.push({
              match: { [key]: value }, // Exact match for non-string fields
            });
          }
        }
      }

      // Default to match_all if no filters are provided
      const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };

      // Execute search query in OpenSearch
      const { body } = await this.client.search({
        index: this.index,
        from,
        size: pageSize,
        body: { query },
      });

      // Extract total number of hits
      const total = body.hits.total instanceof Object ? body.hits.total.value : body.hits.total;

      // Format results
      const results = body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'bundle',
        spec_version: '2.1',
        ...hit._source,
      }));

      return {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results,
      };
    } catch (error) {
      throw new InternalServerErrorException('Error searching bundles in OpenSearch');
    }
  }

  /**
   * Update a bundle
   */
  async update(id: string, updateBundleInput: UpdateBundleInput): Promise<Bundle> {
    try {
      await this.client.update({
        index: this.index,
        id,
        body: {
          doc: updateBundleInput,
          doc_as_upsert: true, // If document doesn't exist, create it
        },
      });

      return this.findOne(id);
    } catch (error) {
      throw new InternalServerErrorException('Error updating bundle in OpenSearch');
    }
  }

  /**
   * Delete a bundle by ID
   */
  async remove(id: string): Promise<boolean> {
    try {
      const { body } = await this.client.delete({
        index: this.index,
        id,
      });

      return body.result === 'deleted';
    } catch (error) {
      return false; // If delete fails, return false instead of throwing an error
    }
  }
}
