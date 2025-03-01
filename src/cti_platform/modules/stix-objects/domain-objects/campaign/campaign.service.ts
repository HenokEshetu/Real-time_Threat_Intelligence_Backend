import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateCampaignInput, UpdateCampaignInput } from './campaign.input';
import { v4 as uuidv4 } from 'uuid';
import { SearchCampaignInput } from './campaign.resolver';
@Injectable()
export class CampaignService {
  private readonly index = 'campaigns'; // OpenSearch index name

  private openSearchClient: Client;

  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  //  Create Campaign
  async create(createCampaignInput: CreateCampaignInput): Promise<any> {
    const campaign = {
      id: `campaign--${uuidv4()}`,
      type: 'campaign',
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createCampaignInput,
    };

    try {
      await this.openSearchClient.index({
        index: this.index,
        id: campaign.id,
        body: campaign,
        refresh: 'wait_for',
      });

      return campaign;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create campaign: ${error.message}`);
    }
  }

  // Find Campaign by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Campaign with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching campaign: ${error.message}`);
    }
  }

  //  Update Campaign
  async update(id: string, updateCampaignInput: UpdateCampaignInput): Promise<any> {
    try {
      const existingCampaign = await this.findOne(id);

      const updatedCampaign = {
        ...existingCampaign,
        ...updateCampaignInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchClient.index({
        index: this.index,
        id,
        body: updatedCampaign,
        refresh: 'wait_for',
      });

      return updatedCampaign;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update campaign: ${error.message}`);
    }
  }

  //  Delete Campaign
  async remove(id: string): Promise<boolean> {
    try {
      const { body } = await this.openSearchClient.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });

      return body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Campaign with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete campaign: ${error.message}`);
    }
  }

  // Search Campaigns with Filters & Pagination
  async searchWithFilters(filters: SearchCampaignInput, page = 1, pageSize = 10): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];
      const shouldQueries = [];
      const filterQueries = [];

      //  Construct dynamic search queries
      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          mustQueries.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          mustQueries.push({ term: { [key]: value } });
        } else if (['created', 'modified'].includes(key)) {
          if (typeof value === 'object' && ('gte' in value || 'lte' in value)) {
            filterQueries.push({ range: { [key]: value } });
          } else {
            filterQueries.push({ range: { [key]: { gte: value } } });
          }
        } else if (typeof value === 'string') {
          if (value.includes('*')) {
            mustQueries.push({ wildcard: { [key]: value.toLowerCase() } });
          } else if (value.includes('~')) {
            shouldQueries.push({ fuzzy: { [key]: { value, fuzziness: 'AUTO' } } });
          } else {
            mustQueries.push({ match_phrase: { [key]: value } });
          }
        }
      }

      //  Construct OpenSearch query
      const query: any = { bool: {} };

      if (mustQueries.length > 0) query.bool.must = mustQueries;
      if (shouldQueries.length > 0) query.bool.should = shouldQueries;
      if (filterQueries.length > 0) query.bool.filter = filterQueries;

      if (Object.keys(query.bool).length === 0) {
        query.bool.must = [{ match_all: {} }];
      }

      //  Execute OpenSearch Query
      const { body } = await this.openSearchClient.search({
        index: this.index,
        from,
        size: pageSize,
        body: {
          query,
          sort: [{ created: { order: 'desc' } }],
        },
      });

      //  Fix: Safely extract `total`
      const total = typeof body.hits.total === 'number' ? body.hits.total : body.hits.total?.value ?? 0;

      return {
        total,
        page,
        pageSize,
        results: body.hits.hits.map((hit) => ({
          id: hit._id,
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException(`Error searching campaigns in OpenSearch: ${error.message}`);
    }
  }
}
