import { Resolver, InputType, Query, Mutation, Args,Int, Subscription } from '@nestjs/graphql';
import { GroupingService } from './grouping.service';
import { Grouping } from './grouping.entity';
import { CreateGroupingInput, UpdateGroupingInput } from './grouping.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Inject } from '@nestjs/common';


@InputType()
export class SearchGroupingInput extends PartialType(CreateGroupingInput){}


@ObjectType()
export class GroupingSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Grouping])
  results: Grouping[];
}

@Resolver(() => Grouping)
export class GroupingResolver {


  constructor(
        private readonly groupingService: GroupingService,
        @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
      ) { }
    
      // Date conversion helper
      public convertDates(payload: any): Grouping {
        const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
        dateFields.forEach(field => {
          if (payload[field]) payload[field] = new Date(payload[field]);
        });
        return payload;
      }
    
      // Subscription Definitions
      @Subscription(() => Grouping, {
        name: 'groupingCreated',
        resolve: (payload) => payload,
      })
    groupingCreated() {
        return this.pubSub.asyncIterator('groupingCreated');
      }
    
      @Subscription(() => Grouping, {
        name: 'groupingUpdated',
        resolve: (payload) => payload,
      })
      groupingUpdated() {
        return this.pubSub.asyncIterator('groupingUpdated');
      }
    
      @Subscription(() => String, { name: 'groupingDeleted' })
      groupingDeleted() {
        return this.pubSub.asyncIterator('groupingDeleted');
      }
  

  @Mutation(() => Grouping)
  async createGrouping(
    @Args('input') createGroupingInput: CreateGroupingInput,
  ): Promise<Grouping> {
    return this.groupingService.create(createGroupingInput);
  }

  @Query(() => GroupingSearchResult)
  async searchGroupings(
    @Args('filters', { type: () => SearchGroupingInput, nullable: true }) filters: SearchGroupingInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<GroupingSearchResult> {
    return this.groupingService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Grouping, { nullable: true })
  async grouping(@Args('id') id: string): Promise<Grouping> {
    return this.groupingService.findOne(id);
  }

  @Mutation(() => Grouping)
  async updateGrouping(
    @Args('id') id: string,
    @Args('input') updateGroupingInput: UpdateGroupingInput,
  ): Promise<Grouping> {
    return this.groupingService.update(id, updateGroupingInput);
  }

  @Mutation(() => Boolean)
  async deleteGrouping(@Args('id') id: string): Promise<boolean> {
    return this.groupingService.remove(id);
  }
}