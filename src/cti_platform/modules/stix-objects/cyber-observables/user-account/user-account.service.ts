import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateUserAccountInput, UpdateUserAccountInput } from './user-account.input';
import { UserAccount } from './user-account.entity';
import { SearchUrlUserAccountInput } from './user-account.resolver';
import { BaseStixService } from '../../base-stix.service';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class UserAccountService extends BaseStixService<UserAccount> implements OnModuleInit {
  protected typeName = ' user-account';
  private readonly index = 'user-accounts';
  private readonly logger = console; // Replace with a proper logger if needed


  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }


  async onModuleInit() {
    await this.ensureIndex();
  }


  async create(createUserAccountInput: CreateUserAccountInput): Promise<UserAccount> {


    const userAccount: UserAccount = {
      ...createUserAccountInput,

      id: createUserAccountInput.id,
      type: 'user-account' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),

    };


    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: userAccount.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: userAccount.id });

      const existingDoc = await this.findOne(userAccount.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: userAccount.id,
        body: userAccount,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index user account document');
      }
      await (userAccount)
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
      const response = await this.openSearchService.get({ index: this.index, id });
      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'user-account' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),

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

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedUser },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update user account document');
      }
      await (updatedUser)
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
      const response = await this.openSearchService.delete({ index: this.index, id });
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
                range: { [key]: { gte: value, lte: value } },
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
          type: 'user-account' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),

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