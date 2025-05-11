import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { NetworkTrafficService } from './network-traffic.service';
import { NetworkTraffic } from './network-traffic.entity';
import { CreateNetworkTrafficInput, UpdateNetworkTrafficInput } from './network-traffic.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
@InputType()
export class SearchNetworkTrafficInput extends PartialType(CreateNetworkTrafficInput) { }

@ObjectType()
export class NetworkTrafficSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [NetworkTraffic])
  results: NetworkTraffic[];
}

@Resolver(() => NetworkTraffic)
export class NetworkTrafficResolver {
 
  constructor(
    private readonly networkTrafficService: NetworkTrafficService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): NetworkTraffic {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => NetworkTraffic, {
    name: 'networkTrafficCreated',
    resolve: (payload) => payload,
  })
  networkTrafficCreated() {
    return this.pubSub.asyncIterator('networkTrafficCreated');
  }

  @Subscription(() => NetworkTraffic, {
    name: 'networkTrafficUpdated',
    resolve: (payload) => payload,
  })
  networkTrafficUpdated() {
    return this.pubSub.asyncIterator('networkTrafficUpdated');
  }

  @Subscription(() => String, { name: 'networkTrafficDeleted' })
  networkTrafficDeleted() {
    return this.pubSub.asyncIterator('networkTrafficDeleted');
  }

  @Mutation(() => NetworkTraffic)
  async createNetworkTraffic(
    @Args('input') createNetworkTrafficInput: CreateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.create(createNetworkTrafficInput);
  }

  @Query(() => NetworkTrafficSearchResult)
  async searchNetworkTraffic(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchNetworkTrafficInput, nullable: true }) filters: SearchNetworkTrafficInput = {},
  ): Promise<NetworkTrafficSearchResult> {
    return this.networkTrafficService.searchWithFilters(from, size, filters);
  }

  @Query(() => NetworkTraffic, { nullable: true })
  async networkTraffic(@Args('id') id: string): Promise<NetworkTraffic> {
    return this.networkTrafficService.findOne(id);
  }

  @Mutation(() => NetworkTraffic)
  async updateNetworkTraffic(
    @Args('id') id: string,
    @Args('input') updateNetworkTrafficInput: UpdateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.update(id, updateNetworkTrafficInput);
  }

  @Mutation(() => Boolean)
  async deleteNetworkTraffic(@Args('id') id: string): Promise<boolean> {
    return this.networkTrafficService.remove(id);
  }
}