import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateUserAccountInput, UpdateUserAccountInput } from './user-account.input';
import { UserAccount } from './user-account.entity';
import { SearchUrlUserAccountInput } from './user-account.resolver';

@Injectable()
export class UserAccountService implements OnModuleInit {
  private readonly index = 'user-accounts';
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


  async create(createUserAccountInput: CreateUserAccountInput): Promise<UserAccount> {
    const userAccount: UserAccount = {
      id: `user-account--${uuidv4()}`,
      type: 'user-account' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createUserAccountInput,
      ...(createUserAccountInput.enrichment ? { enrichment: createUserAccountInput.enrichment } : {}),
    };

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id: userAccount.id,
        body: userAccount,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index user account document');
      }
      return userAccount;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create user account',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<UserAccount> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      const source = response.body._source;
      return {
        id: response.body._id,
        type: 'user-account' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        ...source,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`User account with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch user account',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateUserAccountInput: UpdateUserAccountInput): Promise<UserAccount> {
    try {
      const existingUser = await this.findOne(id);
      const updatedUser: UserAccount = {
        ...existingUser,
        ...updateUserAccountInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedUser },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update user account document');
      }

      return updatedUser;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update user account',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({ index: this.index, id });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete user account',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchUrlUserAccountInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: UserAccount[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'user_id':
          case 'account_login':
          case 'display_name':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'created':
          case 'modified':
          case 'account_created':
          case 'account_expires':
          case 'credential_last_changed':
          case 'account_first_login':
          case 'account_last_login':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
              });
            }
            break;
          case 'is_service_account':
          case 'is_privileged':
          case 'can_escalate_privs':
          case 'is_disabled':
            queryBuilder.query.bool.filter.push({
              term: { [key]: value },
            });
            break;
          default:
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
        }
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.openSearchClient.search({
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
          id: hit._id,
          type: 'user-account' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search user accounts',
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
                user_id: { type: 'keyword' },
                account_login: { type: 'keyword' },
                display_name: { type: 'text' },
                is_service_account: { type: 'boolean' },
                is_privileged: { type: 'boolean' },
                can_escalate_privs: { type: 'boolean' },
                is_disabled: { type: 'boolean' },
                account_created: { type: 'date' },
                account_expires: { type: 'date' },
                credential_last_changed: { type: 'date' },
                account_first_login: { type: 'date' },
                account_last_login: { type: 'date' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize user-accounts index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}