import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client } from '@opensearch-project/opensearch';
import { CreateUserAccountInput, UpdateUserAccountInput } from './user-account.input';
import { UserAccount } from './user-account.entity';
import { SearchUrlUserAccountInput } from './user-account.resolver';
@Injectable()
export class UserAccountService {
  private readonly index = 'user-accounts'; // OpenSearch index name

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  /**
   * Create a new User Account in OpenSearch
   */
  async create(createUserAccountInput: CreateUserAccountInput): Promise<UserAccount> {
    const userAccount: UserAccount = {
      id: `user-account--${uuidv4()}`,
      ...createUserAccountInput,
      created: new Date().toISOString(),

      modified: new Date().toISOString(),

    };

    await this.openSearchClient.index({
      index: this.index,
      id: userAccount.id,
      body: userAccount,
    });

    return userAccount;
  }

  /**
   * Find one User Account by ID
   */
  async findOne(id: string): Promise<UserAccount | null> {
    try {
      const { body } = await this.openSearchClient.get({ index: this.index, id });
      return body._source as UserAccount;
    } catch (error) {
      return null; // Handle not found cases gracefully
    }
  }

  /**
   * Update a User Account in OpenSearch
   */
  async update(id: string, updateUserAccountInput: UpdateUserAccountInput): Promise<UserAccount | null> {
    const existingUser = await this.findOne(id);
    if (!existingUser) {
      throw new Error('User Account not found');
    }

    const updatedUser: UserAccount = {
      ...existingUser,
      ...updateUserAccountInput,
      modified: new Date().toISOString(),

    };

    await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updatedUser },
    });

    return updatedUser;
  }

  /**
   * Delete a User Account from OpenSearch
   */
  async remove(id: string): Promise<boolean> {
    try {
      await this.openSearchClient.delete({ index: this.index, id });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Search User Accounts with dynamic filters
   */
  async searchWithFilters(
    searchParams: SearchUrlUserAccountInput,
    page: number = 1,
    pageSize: number = 10
  ): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];

      // Construct dynamic search query based on provided filters
      for (const [key, value] of Object.entries(searchParams)) {
        if (value !== undefined) {
          if (value instanceof Date) {
            mustQueries.push({ range: { [key]: { gte: value.toISOString() } } });
          } else {
            mustQueries.push({ match: { [key]: value } });
          }
        }
      }

      // Use match_all if no filters are provided
      const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };

      // Execute search query in OpenSearch
      const { body } = await this.openSearchClient.search({
        index: this.index,
        from,
        size: pageSize,
        body: { query },
      });

      // Extract total number of hits
      const total = body.hits.total instanceof Object ? body.hits.total.value : body.hits.total;

      // Map results to the required structure
      const results = body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'user-account',
        spec_version: '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        ...hit._source,
      }));

      // Return results with pagination metadata
      return {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results,
      };
    } catch (error) {
      throw new InternalServerErrorException('Error searching user accounts in OpenSearch');
    }
  }
}
