import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client,} from '@opensearch-project/opensearch';
import { CampaignSearchResult, CreateCampaignInput, UpdateCampaignInput } from './campaign.input';
import { Campaign } from './campaign.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Field, InputType, PartialType } from '@nestjs/graphql';

@InputType()
export class DateRangeInput {
  @Field(() => String, { nullable: true })
  gte?: string;

  @Field(() => String, { nullable: true })
  lte?: string;

  @Field(() => String, { nullable: true })
  gt?: string;

  @Field(() => String, { nullable: true })
  lt?: string;
}

@InputType()
export class SearchCampaignInput extends PartialType(CreateCampaignInput) {
  @Field(() => DateRangeInput, { nullable: true })
  first_seen_range?: DateRangeInput;

  @Field(() => DateRangeInput, { nullable: true })
  last_seen_range?: DateRangeInput;
}

@Injectable()
export class CampaignService extends BaseStixService<Campaign> implements OnModuleInit {
  protected typeName = 'campaign';
  private readonly index = 'campaigns';
  private readonly logger = console;
 

  constructor(
      @Inject(PUB_SUB) pubSub: RedisPubSub,
      @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
    ) {
      super(pubSub);
    }

  async onModuleInit() {
    await this.ensureIndex();
  }
  async create(createCampaignInput: CreateCampaignInput): Promise<Campaign> {
    
    const campaign: Campaign = {
      ...createCampaignInput,
      
      id: createCampaignInput.id,
      type: 'campaign' as const,
      spec_version: '2.1',
      created: new Date().  toISOString(),
      modified: new Date().toISOString(),
      name: createCampaignInput.name, // Required field
     
    };

    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: campaign.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: campaign.id });

      const existingDoc = await this.findOne(campaign.id);
      return existingDoc;

    }


    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: campaign.id,
        body: campaign,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index campaign');
      }
      await this.publishCreated(campaign);
      return campaign;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create campaign',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<Campaign> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'campaign' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Campaign with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch campaign',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateCampaignInput: UpdateCampaignInput): Promise<Campaign> {
    try {
      const existingCampaign = await this.findOne(id);
      const updatedCampaign: Campaign = {
        ...existingCampaign,
        ...updateCampaignInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedCampaign },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update campaign');
      }
      await this.publishUpdated(updatedCampaign);
      return updatedCampaign;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update campaign',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });
      const success = response.body.result === 'deleted';
      if (success) {
        await this.publishDeleted(id);
      }
      return success;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete campaign',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchCampaignInput = {},
    page: number = 1,
    pageSize: number = 10,
  ): Promise<CampaignSearchResult> {
    try {
      // Validate pagination parameters
      if (page < 1 || pageSize < 1) {
        throw new Error('Page and pageSize must be positive integers');
      }
      if (pageSize > 100) {
        throw new Error('pageSize cannot exceed 100');
      }

      const from = (page - 1) * pageSize;
      const query = this.buildSearchQuery(filters);

      const response = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: query,
      });

      return this.transformSearchResponse(response, page, pageSize);
    } catch (error) {
      throw this.handleOpenSearchError(error, 'search campaigns');
    }
  }

  private buildSearchQuery(filters: SearchCampaignInput): any {
    const query: { query: any; sort?: any[] } = {
      query: { bool: { must: [], filter: [], should: [] } },
      sort: [{ modified: { order: 'desc' } }],
    };

    Object.entries(filters).forEach(([key, value]) => {
      if (!value) return;

      // Handle date range filters (e.g., first_seen_range, last_seen_range)
      if (key.endsWith('_range')) {
        const field = key.replace('_range', '');
        this.addDateRangeQuery(query, field, value);
        return;
      }

      // Handle standard filters
      if (Array.isArray(value)) {
        query.query.bool.filter.push({ terms: { [key]: value } });
      } else if (typeof value === 'boolean' || typeof value === 'number') {
        query.query.bool.filter.push({ term: { [key]: value } });
      } else if (['created', 'modified', 'first_seen', 'last_seen'].includes(key)) {
        this.addDateRangeQuery(query, key, value);
      } else if (typeof value === 'string') {
        this.addStringQuery(query, key, value);
      } else if (typeof value === 'object') {
        this.handleNestedFilters(query, key, value);
      }
    });

    this.finalizeQueryStructure(query);
    return query;
  }

  private addDateRangeQuery(query: any, key: string, value: any): void {
    if (typeof value === 'object') {
      const range = this.validateAndConvertRange(value);
      if (range) {
        query.query.bool.filter.push({ range: { [key]: range } });
      }
    }
  }

  private addStringQuery(query: any, key: string, value: string): void {
    if (value.includes('*')) {
      query.query.bool.must.push({
        wildcard: { [key]: { value: value.toLowerCase(), case_insensitive: true } },
      });
    } else if (value.includes('~')) {
      query.query.bool.should.push({
        fuzzy: {
          [key]: {
            value: value.replace('~', ''),
            fuzziness: 'AUTO',
            transpositions: true,
          },
        },
      });
    } else {
      query.query.bool.must.push({
        match: {
          [key]: {
            query: value,
            operator: 'and',
            fuzziness: 0,
          },
        },
      });
    }
  }

  private handleNestedFilters(query: any, key: string, value: any): void {
    // Example for kill_chain_phases or other nested fields
    if (key === 'kill_chain_phases') {
      query.query.bool.filter.push({
        nested: {
          path: 'kill_chain_phases',
          query: {
            bool: {
              must: Object.entries(value).map(([nestedKey, nestedValue]) => ({
                term: { [`kill_chain_phases.${nestedKey}`]: nestedValue },
              })),
            },
          },
        },
      });
    }
  }

  private finalizeQueryStructure(query: any): void {
    if (
      !query.query.bool.must.length &&
      !query.query.bool.filter.length &&
      !query.query.bool.should.length
    ) {
      query.query = { match_all: {} };
    }

    if (query.query.bool.should.length > 0) {
      query.query.bool.minimum_should_match = 1;
    }

    if (query.query.bool.filter.length > 0) {
      query.query.bool.filter = query.query.bool.filter.filter(Boolean);
    }
  }

  private transformOpenSearchResponse(response: any): Campaign {
    const source = response.body._source;
    const dates = ['created', 'modified', 'first_seen', 'last_seen'];

    dates.forEach((field) => {
      if (source[field]) {
        source[field] = new Date(source[field]);
      }
    });

    return {
      ...source,
      id: response.body._id,
      type: 'campaign',
      spec_version: source.spec_version || '2.1',
      created: source.created || new Date(),
      modified: source.modified || new Date(),
      name: source.name, // Required field
    };
  }

  private transformSearchResponse(response: any, page: number, pageSize: number): CampaignSearchResult {
    const total = response.body.hits.total?.value || response.body.hits.total || 0;

    return {
      page,
      pageSize,
      total,
      totalPages: Math.ceil(total / pageSize) || 1,
      results: response.body.hits.hits.map((hit) =>
        this.transformOpenSearchResponse({
          body: {
            _id: hit._id,
            _source: hit._source,
          },
        }),
      ),
    };
  }

  private parseDateInput(input?: string): Date | null {
    if (!input) return null;

    if (/^\d{4}-\d{2}-\d{2}$/.test(input)) {
      return new Date(`${input}T00:00:00Z`);
    }

    const date = new Date(input);
    return isNaN(date.getTime()) ? null : date;
  }

  private validateAndConvertRange(range?: any): any {
    if (!range) return null;

    const converted: any = {};
    const operators = ['gte', 'lte', 'gt', 'lt'] as const;

    operators.forEach((op) => {
      if (range[op]) {
        const date = this.parseDateInput(range[op]);
        if (!date) throw new Error(`Invalid date format for ${op}: ${range[op]}`);
        converted[op] = date.toISOString();
      }
    });

    // Validate logical consistency
    if (converted.gte && converted.lte && new Date(converted.gte) > new Date(converted.lte)) {
      throw new Error('gte cannot be later than lte');
    }
    if (converted.gt && converted.lt && new Date(converted.gt) >= new Date(converted.lt)) {
      throw new Error('gt cannot be equal to or later than lt');
    }

    return converted;
  }

  private handleOpenSearchError(error: any, operation: string): InternalServerErrorException {
    let details = error.message;
    let errorType = 'UnknownError';

    if (error.meta?.body?.error) {
      errorType = error.meta.body.error.type || 'OpenSearchError';
      details = error.meta.body.error.reason || JSON.stringify(error.meta.body.error);
    }

    this.logger.error(`OpenSearch ${operation} error (${errorType}): ${details}`);

    return new InternalServerErrorException({
      message: `Failed to ${operation}`,
      details,
      errorType,
    });
  }
  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchService.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchService.indices.create({
          index: this.index,
          body: {
            mappings: {
              dynamic: 'true',
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                name: { type: 'text' },
                description: { type: 'text' },
                aliases: { type: 'keyword' },
                first_seen: { type: 'date' },
                last_seen: { type: 'date' },
                objective: { type: 'text' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize campaigns index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}