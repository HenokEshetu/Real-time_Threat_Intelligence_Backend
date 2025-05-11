import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { IntrusionSetService } from './intrusion-set.service';
import { CreateIntrusionSetInput, UpdateIntrusionSetInput } from './intrusion-set.input';
import { IntrusionSet } from './intrusion-set.entity';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';
@InputType()
export class SearchIntrusionSetInput extends PartialType(CreateIntrusionSetInput) { }

@ObjectType()
export class IntrusionSetSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [IntrusionSet])
  results: IntrusionSet[];
}

@Resolver(() => IntrusionSet)
export class IntrusionSetResolver {
  constructor(
    private readonly intrusionSetService: IntrusionSetService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): IntrusionSet {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => IntrusionSet, {
    name: 'intrusionSetCreated',
    resolve: (payload) => payload,
  })
  intrusionSetCreated() {
    return this.pubSub.asyncIterator('intrusionSetCreated');
  }

  @Subscription(() => IntrusionSet, {
    name: 'intrusionSetUpdated',
    resolve: (payload) => payload,
  })
 intrusionSetUpdated() {
    return this.pubSub.asyncIterator('intrusionSetUpdated');
  }

  @Subscription(() => String, { name: 'intrusionSetDeleted' })
  intrusionSetDeleted() {
    return this.pubSub.asyncIterator('intrusionSetDeleted');
  }
  @Mutation(() => IntrusionSet)
  async createIntrusionSet(
    @Args('input') createIntrusionSetInput: CreateIntrusionSetInput,
  ): Promise<IntrusionSet> {
    return this.intrusionSetService.create(createIntrusionSetInput);
  }

  @Query(() => IntrusionSetSearchResult)
  async searchIntrusionSets(
    @Args('filters', { type: () => SearchIntrusionSetInput, nullable: true }) filters: SearchIntrusionSetInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IntrusionSetSearchResult> {
    return this.intrusionSetService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => IntrusionSet, { nullable: true })
  async intrusionSet(@Args('id') id: string): Promise<IntrusionSet> {
    return this.intrusionSetService.findOne(id);
  }

  @Mutation(() => IntrusionSet)
  async updateIntrusionSet(
    @Args('id') id: string,
    @Args('input') updateIntrusionSetInput: UpdateIntrusionSetInput,
  ): Promise<IntrusionSet> {
    return this.intrusionSetService.update(id, updateIntrusionSetInput);
  }

  @Mutation(() => Boolean)
  async deleteIntrusionSet(@Args('id') id: string): Promise<boolean> {
    return this.intrusionSetService.remove(id);
  }
}