import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit, Logger } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { CreateEmailMessageInput, UpdateEmailMessageInput,  } from './email-message.input';
import { SearchEmailMessageInput } from './email-message.resolver';
import { EmailMessage } from './email-message.entity';
import { BaseStixService } from '../../base-stix.service';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';

import { v5 as uuidv5 } from 'uuid';
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

@Injectable()
export class EmailMessageService extends BaseStixService<EmailMessage> implements OnModuleInit {
  protected typeName = 'email-message';
  private readonly index = 'email-messages';
  private readonly logger = new Logger(EmailMessageService.name);

  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createEmailMessageInput: CreateEmailMessageInput): Promise<EmailMessage> {
    this.validateEmailMessage(createEmailMessageInput);

    const timestamp = new Date();
    
    const doc: EmailMessage = {
      ...createEmailMessageInput,
      id: createEmailMessageInput.id,
      type: 'email-message' as const,
      spec_version: '2.1',

      from_ref: createEmailMessageInput.from_ref,
      to_refs: createEmailMessageInput.to_refs || [],
      cc_refs: createEmailMessageInput.cc_refs || [],
      bcc_refs: createEmailMessageInput.bcc_refs || [],
      subject: createEmailMessageInput.subject || '',
      date: createEmailMessageInput.date || timestamp,
      content_type: createEmailMessageInput.content_type || 'text/plain',
      body: createEmailMessageInput.body || '',
      message_id: createEmailMessageInput.message_id || undefined,
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
        throw new Error('Failed to create email message');
      }

      await this.publishCreated(doc);
      return doc;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create email message',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
  

  async update(id: string, updateEmailMessageInput: UpdateEmailMessageInput): Promise<EmailMessage> {
    this.validateEmailMessage(updateEmailMessageInput);

    try {
      const existing = await this.findOne(id); 
      const updatedDoc: Partial<EmailMessage> = {
        ...updateEmailMessageInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update email message');
      }

      const updatedEmailMessage: EmailMessage = {
        ...existing,
        ...updatedDoc,
        type: 'email-message' as const,
        spec_version: existing.spec_version || '2.1',
      };

      await this.publishUpdated(updatedEmailMessage);
      return updatedEmailMessage;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update email message',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<EmailMessage> {
    try {
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;

      return {
        ...source,
        id,
        type: 'email-message' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        from_ref: source.from_ref || '',
        to_refs: source.to_refs || [],
        cc_refs: source.cc_refs || [],
        bcc_refs: source.bcc_refs || [],
        subject: source.subject || '',
        date: source.date || new Date(),
        content_type: source.content_type || 'text/plain',
        body: source.body || '',
        message_id: source.message_id || undefined,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`EmailMessage with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch email message',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchEmailMessageInput = {},
    from: number = 0,
    size: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: EmailMessage[];
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
          case 'subject':
          case 'body':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'from_ref':
          case 'message_id':
          case 'content_type':
            queryBuilder.query.bool.must.push({
              term: { [key]: value },
            });
            break;
          case 'to_refs':
          case 'cc_refs':
          case 'bcc_refs':
            queryBuilder.query.bool.filter.push({
              terms: { [key]: Array.isArray(value) ? value : [value] },
            });
            break;
          case 'created':
          case 'modified':
          case 'date':
            const dateValue = typeof value === 'string' ? value : value instanceof Date ? value : null;
            if (dateValue) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: dateValue, lte: dateValue } },
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
          type: 'email-message' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          from_ref: hit._source.from_ref || '',
          to_refs: hit._source.to_refs || [],
          cc_refs: hit._source.cc_refs || [],
          bcc_refs: hit._source.bcc_refs || [],
          subject: hit._source.subject || '',
          date: hit._source.date || new Date(),
          content_type: hit._source.content_type || 'text/plain',
          body: hit._source.body || '',
          message_id: hit._source.message_id || undefined,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search email messages',
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
      return success;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete email message',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateEmailMessage(input: CreateEmailMessageInput | UpdateEmailMessageInput): void {
    // Check required fields for creation
    if ('from_ref' in input && input.from_ref === undefined && !('id' in input)) {
      throw new StixValidationError('from_ref is required for creating an email message');
    }

    // Validate from_ref if provided
    if ('from_ref' in input && input.from_ref !== undefined && input.from_ref !== null) {
      if (typeof input.from_ref !== 'string' || !this.isValidStixId(input.from_ref, 'email-addr')) {
        throw new StixValidationError('from_ref must be a valid email-addr STIX identifier');
      }
    }

    // Validate to_refs, cc_refs, bcc_refs if provided
    ['to_refs', 'cc_refs', 'bcc_refs'].forEach((field) => {
      if (field in input && input[field] !== undefined && input[field] !== null) {
        if (!Array.isArray(input[field]) || !input[field].every(ref => typeof ref === 'string' && this.isValidStixId(ref, 'email-addr'))) {
          throw new StixValidationError(`${field} must be an array of valid email-addr STIX identifiers`);
        }
      }
    });

    // Validate subject if provided
    if ('subject' in input && input.subject !== undefined && input.subject !== null) {
      if (typeof input.subject !== 'string' || input.subject.length > 998) {
        throw new StixValidationError('subject must be a string with a maximum length of 998 characters');
      }
    }

    // Validate date if provided
    if ('date' in input && input.date !== undefined && input.date !== null) {
      if (typeof input.date !== 'string' || !this.isValidDate(input.date)) {
        throw new StixValidationError('date must be a valid ISO 8601 timestamp');
      }
    }

    // Validate content_type if provided
    if ('content_type' in input && input.content_type !== undefined && input.content_type !== null) {
      if (typeof input.content_type !== 'string' || !this.isValidContentType(input.content_type)) {
        throw new StixValidationError('content_type must be a valid MIME type (e.g., text/plain)');
      }
    }

    // Validate body if provided
    if ('body' in input && input.body !== undefined && input.body !== null) {
      if (typeof input.body !== 'string') {
        throw new StixValidationError('body must be a string');
      }
    }

    // Validate message_id if provided
    if ('message_id' in input && input.message_id !== undefined && input.message_id !== null) {
      if (typeof input.message_id !== 'string' || input.message_id.length > 256) {
        throw new StixValidationError('message_id must be a string with a maximum length of 256 characters');
      }
    }

    // Validate spec_version if provided
    if ('spec_version' in input && input.spec_version && input.spec_version !== '2.1') {
      throw new StixValidationError('EmailMessage spec_version must be 2.1');
    }
  }

  private isValidStixId(id: string, expectedType: string): boolean {
    // Basic STIX ID validation: [type]--[UUID]
    const regex = new RegExp(`^${expectedType}--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, 'i');
    return regex.test(id);
  }

  private isValidDate(date: Date): boolean {
    try {
      const parsedDate = new Date(date);
      return !isNaN(parsedDate.getTime()) && parsedDate === date;
    } catch {
      return false;
    }
  }
  private isValidContentType(contentType: string): boolean {
    return /^[a-zA-Z0-9][a-zA-Z0-9-+.]*\/[a-zA-Z0-9][a-zA-Z0-9-+.]*$/.test(contentType);
  }

  private async ensureIndex(): Promise<void> {
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
                date: { type: 'date' },
                from_ref: { type: 'keyword' },
                to_refs: { type: 'keyword' },
                cc_refs: { type: 'keyword' },
                bcc_refs: { type: 'keyword' },
                subject: { type: 'text' },
                content_type: { type: 'keyword' },
                body: { type: 'text' },
                message_id: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize email-messages index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}