import { Inject, Injectable, InternalServerErrorException, NotFoundException,  OnModuleInit } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { EmailAddress } from './email-address.entity';
import { CreateEmailAddressInput, UpdateEmailAddressInput } from './email-address.input';
import { SearchEmailAddressInput } from './email-address.resolver';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { StixValidationError } from 'src/cti_platform/core/exception/custom-exceptions';
import { v5 as uuidv5 } from 'uuid';
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
@Injectable()
export class EmailAddressService extends BaseStixService<EmailAddress> implements OnModuleInit {
  private readonly logger = new (console as any).constructor(); // Replace with a proper logger if available
  protected typeName = 'email-ddaress';
  private readonly index = 'email-addresses';


  constructor(
              @Inject(PUB_SUB) pubSub: RedisPubSub,
              @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
            ) {
              super(pubSub);
            }

  async onModuleInit() {
    await this.ensureIndex();}
    
    async create(createEmailAddressInput: CreateEmailAddressInput): Promise<EmailAddress> {
      this.validateEmailAddress(createEmailAddressInput);
  
      const timestamp = new Date();
      
  
      const doc: EmailAddress = {
        ...createEmailAddressInput,
        id: createEmailAddressInput.id,
        type: 'email-addr' as const,
        spec_version: '2.1',
        created: timestamp.toISOString(),
        modified: timestamp.toISOString(),
        value: createEmailAddressInput.value, 
        display_name: createEmailAddressInput.display_name || '',
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
          throw new Error('Failed to create email address');
        }
  
        await this.publishCreated(doc);
        return doc;
      } catch (error) {
        throw new InternalServerErrorException({
          message: 'Failed to create email address',
          details: error.meta?.body?.error || error.message,
        });
      }
    }
  
    async update(id: string, updateEmailAddressInput: UpdateEmailAddressInput): Promise<EmailAddress> {
      this.validateEmailAddress(updateEmailAddressInput);
  
      try {
        const existing = await this.findOne(id);
        const updatedDoc: Partial<EmailAddress> = {
          ...updateEmailAddressInput,
          modified: new Date().toISOString(),
        };
  
        const response = await this.openSearchService.update({
          index: this.index,
          id,
          body: { doc: updatedDoc },
          retry_on_conflict: 3,
        });
  
        if (response.body.result !== 'updated') {
          throw new Error('Failed to update email address');
        }
  
        const updatedEmailAddress: EmailAddress = {
          ...existing,
          ...updatedDoc,
          type: 'email-addr' as const,
          spec_version: existing.spec_version || '2.1',
        };
  
        await this.publishUpdated(updatedEmailAddress);
        return updatedEmailAddress;
      } catch (error) {
        if (error instanceof NotFoundException) throw error;
        throw new InternalServerErrorException({
          message: 'Failed to update email address',
          details: error.meta?.body?.error || error.message,
        });
      }
    }
  
    private validateEmailAddress(input: CreateEmailAddressInput | UpdateEmailAddressInput): void {
      // Check if value is provided (required for creation)
      if ('value' in input && input.value === undefined && !('id' in input)) {
        throw new StixValidationError('Email address value is required for creation');
      }
  
      // Validate email format if provided
      if (input.value !== undefined && input.value !== null) {
        if (typeof input.value !== 'string' || !this.isValidEmail(input.value)) {
          throw new StixValidationError('Invalid email address. Must be a valid email (e.g., user@example.com)');
        }
      }
  
      // Validate display_name if provided
      if ('display_name' in input && input.display_name !== undefined && input.display_name !== null) {
        if (typeof input.display_name !== 'string' || input.display_name.length > 256) {
          throw new StixValidationError('display_name must be a string with a maximum length of 256 characters');
        }
      }
  
      // Validate spec_version if provided
      if ('spec_version' in input && input.spec_version && input.spec_version !== '2.1') {
        throw new StixValidationError('EmailAddress spec_version must be 2.1');
      }
  
      // Validate belongs_to_ref if provided
      if ('belongs_to_ref' in input && input.belongs_to_ref) {
        if (typeof input.belongs_to_ref !== 'string') {
          throw new StixValidationError('belongs_to_ref must be a valid STIX identifier');
        }
      }
    }
  
    private isValidEmail(email: string): boolean {
      if (!email || email.trim() === '') {
        return false;
      }
  
      // Regular expression for email validation (RFC 5322 simplified)
      const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+$/;
  
      return (
        emailRegex.test(email) &&
        !/[\x00-\x1F\x7F]/.test(email) && // No control characters
        email.length <= 320 // Max length per RFC 5321
      );
    }
  
  async findOne(id: string): Promise<EmailAddress> {
    try {
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;

      return {
        ...source,
        id,
        type: 'email-addr' as const,
        spec_version: '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        value: source.value,
        display_name: source.display_name || '',
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`EmailAddress with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch email address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByValue(value: string): Promise<EmailAddress[]> {
    try {
      const response = await this.openSearchService.search({
        index: this.index,
        body: {
          query: { term: { value } },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
        type: 'email-addr' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date(),
        modified: hit._source.modified || new Date(),
        value: hit._source.value,
        display_name: hit._source.display_name || '',
       
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to find email addresses by value',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByDisplayName(displayName: string): Promise<EmailAddress[]> {
    try {
      const response = await this.openSearchService.search({
        index: this.index,
        body: {
          query: { match: { display_name: { query: displayName, lenient: true } } },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'email-addr' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date(),
        modified: hit._source.modified || new Date(),
        value: hit._source.value,
        display_name: hit._source.display_name || '',
        ...hit._source,
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to find email addresses by display name',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchEmailAddressInput = {},
    from: number = 0,
    size: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: EmailAddress[];
  }> {
    try {
      const queryBuilder: { query: any; sort?: any[] } = {
        query: {
          bool: {
            must: [],
            filter: [],
          },
        },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'value':
          case 'display_name':
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
        size,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;

      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results: response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          type: 'email-addr' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          value: hit._source.value,
          display_name: hit._source.display_name || '',
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search email addresses',
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
        message: 'Failed to delete email address',
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
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                value: { type: 'text' },
                display_name: { type: 'text' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize email-addresses index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}