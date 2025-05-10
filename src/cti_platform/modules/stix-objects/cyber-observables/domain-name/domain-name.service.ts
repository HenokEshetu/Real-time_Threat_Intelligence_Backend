import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client,  } from '@opensearch-project/opensearch';
import { DomainName } from './domain-name.entity';
import { CreateDomainNameInput, UpdateDomainNameInput } from './domain-name.input';
import { SearchDomainNameInput } from './domain-name.resolver';
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
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: DomainName[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const queryBuilder: { query: any; sort?: any[] } = {
        query: {
          bool: {
            must: [],
            filter: [],
          },
        },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(filters)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'value':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'created':
          case 'modified':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value, lte: value } },
              });
            }
            break;
          default:
            queryBuilder.query.bool.must.push({
              term: { [key]: value },
            });
        }
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;

      return {
        
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results: response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          type: 'domain-name' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          value: hit._source.value,
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search domain names',
        details: error.meta?.body?.error || error.message,
      });
    }
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