import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client,  } from '@opensearch-project/opensearch';
import { DomainName } from './domain-name.entity';
import { CreateDomainNameInput, DomainNameSearchResult, UpdateDomainNameInput } from './domain-name.input';
import { SearchDomainNameInput } from './domain-name.input';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { StixValidationError } from 'src/cti_platform/core/exception/custom-exceptions';


@Injectable()
export class DomainNameService  extends BaseStixService<DomainName> implements OnModuleInit {
  private readonly logger = console; // Replace with a proper logger if available
  protected typeName = 'domain-name';
  private readonly index = 'domain-names';
 

  constructor(
            @Inject(PUB_SUB) pubSub: RedisPubSub,
            @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
          ) {
            super(pubSub);
          }

  async onModuleInit() {
    await this.ensureIndex();}
    
      

  async create(createDomainNameInput: CreateDomainNameInput): Promise<DomainName> {

    
    const now = new Date();

    const doc: DomainName = {
      ...createDomainNameInput,
      id: createDomainNameInput.id ,
      type: 'domain-name' as const,
      spec_version: '2.1',
      created: createDomainNameInput.created || now.toDateString(),
      modified: createDomainNameInput.modified || now.toDateString(),
      value: createDomainNameInput.value,
      
    };
    
// Check if document already exists
const exists = await this.openSearchService.exists({
  index: this.index,
  id: doc.id,
});

if (exists.body) {
  this.logger?.warn(`Document already exists`, { id: doc.id });
  
  const existingDoc = await this.findOne(doc.id);
  return existingDoc;
  
}
    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: doc.id,
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }
      await this.publishCreated(doc);
      return doc;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create domain name',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateDomainNameInput: UpdateDomainNameInput): Promise<DomainName> {
    this.validateDomainName(updateDomainNameInput);

    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<DomainName> = {
        ...updateDomainNameInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update domain name');
      }

      const updatedDomainName: DomainName = {
        ...existing,
        ...updatedDoc,
        type: 'domain-name' as const,
        spec_version: existing.spec_version || '2.1',
      };

      await this.publishUpdated(updatedDomainName);
      return updatedDomainName;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update domain name',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateDomainName(input: CreateDomainNameInput | UpdateDomainNameInput): void {
    if ('value' in input && input.value === undefined && !('id' in input)) {
      throw new StixValidationError('Domain name value is required for creation');
    }

    if (input.value !== undefined && input.value !== null) {
      if (typeof input.value !== 'string' || !this.isValidDomainName(input.value)) {
        throw new StixValidationError(
          'Invalid domain name. Must be a valid domain (e.g., example.com)'
        );
      }
    }

    if ('spec_version' in input && input.spec_version && input.spec_version !== '2.1') {
      throw new StixValidationError('DomainName spec_version must be 2.1');
    }

    if ('resolves_to_refs' in input && input.resolves_to_refs) {
      if (!Array.isArray(input.resolves_to_refs) || !input.resolves_to_refs.every(ref => typeof ref === 'string')) {
        throw new StixValidationError('resolves_to_refs must be an array of valid STIX identifiers');
      }
    }
  }

  private isValidDomainName(domain: string): boolean {
    if (!domain || domain.trim() === '') {
      return false;
    }

    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

    return (
      domainRegex.test(domain) &&
      !/[\x00-\x1F\x7F]/.test(domain) &&
      domain.length <= 253 &&
      !/^\.|\.$/.test(domain)
    );
  }

  async findOne(id: string): Promise<DomainName> {
    try {
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;

      return {
        ...source,
        id,
        type: 'domain-name' as const,
        spec_version: '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        value: source.value,
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`DomainName with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch domain name',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByValue(value: string): Promise<DomainName[]> {
    try {
      const response = await this.openSearchService.search({
        index: this.index,
        body: {
          query: { match: { value: { query: value, lenient: true } } },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
        type: 'domain-name' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date(),
        modified: hit._source.modified || new Date(),
        value: hit._source.value,
        
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to find domain names by value',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

   async searchWithFilters(
    filters: SearchDomainNameInput = {},
    page: number = 1,
    pageSize: number = 10,
  ): Promise<DomainNameSearchResult> {
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
      throw this.handleOpenSearchError(error, 'search domain names');
    }
  }

  private buildSearchQuery(filters: SearchDomainNameInput): any {
    const query: { query: any; sort?: any[] } = {
      query: { bool: { must: [], filter: [], should: [] } },
      sort: [{ modified: { order: 'desc' } }],
    };

    Object.entries(filters).forEach(([key, value]) => {
      if (value === undefined || value === null) return;

      // Handle date range filters (e.g., created_range, modified_range)
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
      } else if (['created', 'modified'].includes(key)) {
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
            lenient: true,
          },
        },
      });
    }
  }

  private handleNestedFilters(query: any, key: string, value: any): void {
    // Add support for nested fields if applicable (e.g., resolves_to_refs)
    if (key === 'resolves_to_refs') {
      query.query.bool.filter.push({
        nested: {
          path: 'resolves_to_refs',
          query: {
            bool: {
              must: Object.entries(value).map(([nestedKey, nestedValue]) => ({
                term: { [`resolves_to_refs.${nestedKey}`]: nestedValue },
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

  private transformOpenSearchResponse(response: any): DomainName {
    const source = response.body._source;
    const dates = ['created', 'modified'];

    dates.forEach((field) => {
      if (source[field]) {
        source[field] = new Date(source[field]);
      }
    });

    return {
      ...source,
      id: response.body._id,
      type: 'domain-name',
      spec_version: source.spec_version || '2.1',
      created: source.created || new Date(),
      modified: source.modified || new Date(),
      value: source.value, // Required field
    };
  }

  private transformSearchResponse(response: any, page: number, pageSize: number): DomainNameSearchResult {
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

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
      });
      const success = response.body.result === 'deleted';
      if (success) {
        await this.publishDeleted(id);
      }
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete domain name',
        details: error.meta?.body?.error || error.message,
      });
    }
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
                value: { type: 'text' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize domain-names index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}