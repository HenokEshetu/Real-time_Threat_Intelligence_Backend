import { Injectable, InternalServerErrorException, NotFoundException,  OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { EmailAddress } from './email-address.entity';
import { CreateEmailAddressInput, UpdateEmailAddressInput } from './email-address.input';
import { SearchEmailAddressInput } from './email-address.resolver';

@Injectable()
export class EmailAddressService implements OnModuleInit {
  private readonly index = 'email-addresses';
  private readonly openSearchClient: Client;

  constructor() {
    const clientOptions: ClientOptions = {
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
      ssl: process.env.OPENSEARCH_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      auth: process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD
        ? {
            username: process.env.OPENSEARCH_USERNAME,
            password: process.env.OPENSEARCH_PASSWORD,
          }
        : undefined,
    };
    this.openSearchClient = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();}
    
  async create(createEmailAddressInput: CreateEmailAddressInput): Promise<EmailAddress> {
    const id = `email-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const now = new Date().toISOString();

    const doc: EmailAddress = {
      id,
      type: 'email-addr' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
      value: createEmailAddressInput.value,
      display_name: createEmailAddressInput.display_name || '',
      ...createEmailAddressInput,
    };

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }
      return doc;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create email address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateEmailAddressInput: UpdateEmailAddressInput): Promise<EmailAddress> {
    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<EmailAddress> = {
        ...updateEmailAddressInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update document');
      }

      return { ...existing, ...updatedDoc };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update email address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<EmailAddress> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;

      return {
        id,
        type: 'email-addr' as const,
        spec_version: '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        value: source.value,
        display_name: source.display_name || '',
        ...source,
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
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: { term: { value } },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'email-addr' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        value: hit._source.value,
        display_name: hit._source.display_name || '',
        ...hit._source,
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
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: { match: { display_name: { query: displayName, lenient: true } } },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'email-addr' as const,
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
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
                range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
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

      const response = await this.openSearchClient.search({
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
          id: hit._id,
          type: 'email-addr' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          value: hit._source.value,
          display_name: hit._source.display_name || '',
          ...hit._source,
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
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });
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
      const exists = await this.openSearchClient.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchClient.indices.create({
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