import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { CreateIntrusionSetInput, IntrusionSetSearchResult, UpdateIntrusionSetInput } from './intrusion-set.input';
import { SearchIntrusionSetInput } from './intrusion-set.input';
import { IntrusionSet } from './intrusion-set.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class IntrusionSetService  extends BaseStixService<IntrusionSet> implements OnModuleInit {
  private readonly logger = console; // Replace with a proper logger if needed
  protected typeName = 'intrusion-set';
  private readonly index = 'intrusion-sets';

  constructor(
          @Inject(PUB_SUB) pubSub: RedisPubSub,
          @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
        ) {
          super(pubSub);
        }
    

  async onModuleInit() {
    await this.ensureIndex();
  }
  async create(createIntrusionSetInput: CreateIntrusionSetInput): Promise<IntrusionSet> {

    const intrusionSet: IntrusionSet = {
      ...createIntrusionSetInput,
      id: createIntrusionSetInput.id,
      type: 'intrusion-set' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: createIntrusionSetInput.name, // Required field
      
    };

    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: intrusionSet.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: intrusionSet.id });

      const existingDoc = await this.findOne(intrusionSet.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: intrusionSet.id,
        body: intrusionSet,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index intrusion set');
      }
      await this.publishCreated(intrusionSet);
      return intrusionSet;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create intrusion set',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<IntrusionSet> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'intrusion-set' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        name: source.name, // Required field
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Intrusion set with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch intrusion set',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateIntrusionSetInput: UpdateIntrusionSetInput): Promise<IntrusionSet> {
    try {
      const existingIntrusionSet = await this.findOne(id);
      const updatedIntrusionSet: IntrusionSet = {
        ...existingIntrusionSet,
        ...updateIntrusionSetInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedIntrusionSet },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update intrusion set');
      }
      await this.publishUpdated(updatedIntrusionSet);
      return updatedIntrusionSet;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update intrusion set',
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
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete intrusion set',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchIntrusionSetInput = {},
    page: number = 1,
    pageSize: number = 10,
  ): Promise<IntrusionSetSearchResult> {
    try {
      // Validate pagination parameters
      if (page < 1) throw new Error('Page must be at least 1');
      if (pageSize < 1 || pageSize > 100) throw new Error('PageSize must be between 1 and 100');

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
      throw this.handleOpenSearchError(error, 'search intrusion sets');
    }
  }

  private buildSearchQuery(filters: SearchIntrusionSetInput): any {
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

  private transformOpenSearchResponse(response: any): IntrusionSet {
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
      type: 'intrusion-set',
      spec_version: source.spec_version || '2.1',
      created: source.created || new Date(),
      modified: source.modified || new Date(),
      name: source.name, // Required field
    };
  }

  private transformSearchResponse(response: any, page: number, pageSize: number): IntrusionSetSearchResult {
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
                goals: { type: 'text' },
                resource_level: { type: 'keyword' },
                primary_motivation: { type: 'keyword' },
                secondary_motivations: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize intrusion-sets index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}