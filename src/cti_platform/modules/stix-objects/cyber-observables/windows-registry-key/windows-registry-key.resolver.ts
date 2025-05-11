import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { WindowsRegistryKeyService } from './windows-registry-key.service';
import { WindowsRegistryKey } from './windows-registry-key.entity';
import { CreateWindowsRegistryKeyInput, UpdateWindowsRegistryKeyInput } from './windows-registry-key.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';


@InputType()
export class SearchWindowsRegistryKeyInput extends PartialType(CreateWindowsRegistryKeyInput) { }



@ObjectType()
export class WindowsRegistryKeySearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [WindowsRegistryKey])
  results: WindowsRegistryKey[];
}

@Resolver(() => WindowsRegistryKey)
export class WindowsRegistryKeyResolver {
  
  constructor(
    private readonly windowsRegistryKeyService: WindowsRegistryKeyService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): WindowsRegistryKey {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => WindowsRegistryKey, {
    name: 'windowsRegistryKeyCreated',
    resolve: (payload) => payload,
  })
  windowsRegistryKeyCreated() {
    return this.pubSub.asyncIterator('windowsRegistryKeyCreated');
  }

  @Subscription(() => WindowsRegistryKey, {
    name: 'windowsRegistryKeyUpdated',
    resolve: (payload) => payload,
  })
  windowsRegistryKeyUpdated() {
    return this.pubSub.asyncIterator('windowsRegistryKeyUpdated');
  }

  @Subscription(() => String, { name: 'windowsRegistryKeyDeleted' })
  windowsRegistryKeyDeleted() {
    return this.pubSub.asyncIterator('windowsRegistryKeyDeleted');
  }


  @Mutation(() => WindowsRegistryKey)
  async createWindowsRegistryKey(
    @Args('input') createWindowsRegistryKeyInput: CreateWindowsRegistryKeyInput,
  ): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.create(createWindowsRegistryKeyInput);
  }

  @Query(() => WindowsRegistryKeySearchResult)
  async searchWindowsRegistryKeys(
    @Args('filters', { type: () => SearchWindowsRegistryKeyInput, nullable: true }) filters: SearchWindowsRegistryKeyInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<WindowsRegistryKeySearchResult> {
    return this.windowsRegistryKeyService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => WindowsRegistryKey, { nullable: true })
  async windowsRegistryKey(@Args('id') id: string): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.findOne(id);
  }

  @Mutation(() => WindowsRegistryKey)
  async updateWindowsRegistryKey(
    @Args('id') id: string,
    @Args('input') updateWindowsRegistryKeyInput: UpdateWindowsRegistryKeyInput,
  ): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.update(id, updateWindowsRegistryKeyInput);
  }

  @Mutation(() => Boolean)
  async deleteWindowsRegistryKey(@Args('id') id: string): Promise<boolean> {
    return this.windowsRegistryKeyService.remove(id);
  }
}