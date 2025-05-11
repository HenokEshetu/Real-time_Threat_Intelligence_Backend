import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { UserAccountService } from './user-account.service';
import { UserAccount } from './user-account.entity';
import { CreateUserAccountInput, UpdateUserAccountInput } from './user-account.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';

@InputType()
export class SearchUrlUserAccountInput extends PartialType(CreateUserAccountInput) { }

@ObjectType()
export class UserAccountSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [UserAccount])
  results: UserAccount[];
}

@Resolver(() => UserAccount)
export class UserAccountResolver {

  constructor(
    private readonly userAccountService: UserAccountService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): UserAccount {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => UserAccount, {
    name: 'userAccountCreated',
    resolve: (payload) => payload,
  })
  userAccountCreated() {
    return this.pubSub.asyncIterator('userAccountCreated');
  }

  @Subscription(() => UserAccount, {
    name: 'userAccountUpdated',
    resolve: (payload) => payload,
  })
  userAccountUpdated() {
    return this.pubSub.asyncIterator('userAccountUpdated');
  }

  @Subscription(() => String, { name: 'userAccountDeleted' })
  userAccountDeleted() {
    return this.pubSub.asyncIterator('userAccountDeleted');
  }


  @Mutation(() => UserAccount)
  async createUserAccount(
    @Args('input') createUserAccountInput: CreateUserAccountInput,
  ): Promise<UserAccount> {
    return this.userAccountService.create(createUserAccountInput);
  }

  @Query(() => UserAccountSearchResult)
  async searchUserAccounts(
    @Args('filters', { type: () => SearchUrlUserAccountInput, nullable: true }) filters: SearchUrlUserAccountInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<UserAccountSearchResult> {
    return this.userAccountService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => UserAccount, { nullable: true })
  async userAccount(@Args('id') id: string): Promise<UserAccount> {
    return this.userAccountService.findOne(id);
  }

  @Mutation(() => UserAccount)
  async updateUserAccount(
    @Args('id') id: string,
    @Args('input') updateUserAccountInput: UpdateUserAccountInput,
  ): Promise<UserAccount> {
    return this.userAccountService.update(id, updateUserAccountInput);
  }

  @Mutation(() => Boolean)
  async deleteUserAccount(@Args('id') id: string): Promise<boolean> {
    return this.userAccountService.remove(id);
  }
}