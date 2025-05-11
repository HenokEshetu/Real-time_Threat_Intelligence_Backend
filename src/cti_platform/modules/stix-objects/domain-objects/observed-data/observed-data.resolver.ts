import { Resolver, Query,InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { ObservedDataService } from './observed-data.service';
import { ObservedData } from './observed-data.entity';
import { CreateObservedDataInput, UpdateObservedDataInput } from './observed-data.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';


@InputType()
export class SearchObservedDataInput extends PartialType(CreateObservedDataInput){}


@ObjectType()
export class ObservedDataSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [ObservedData])
  results: ObservedData[];
}

@Resolver(() => ObservedData)
export class ObservedDataResolver  {

  
  constructor(
        private readonly observedDataService: ObservedDataService,
        @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
      ) { }
    
      // Date conversion helper
      public convertDates(payload: any): ObservedData {
        const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
        dateFields.forEach(field => {
          if (payload[field]) payload[field] = new Date(payload[field]);
        });
        return payload;
      }
    
      // Subscription Definitions
      @Subscription(() => ObservedData, {
        name: 'observedDataCreated',
        resolve: (payload) => payload,
      })
      observedDataCreated() {
        return this.pubSub.asyncIterator('observedDataCreated');
      }
    
      @Subscription(() => ObservedData, {
        name: 'observedDataUpdated',
        resolve: (payload) => payload,
      })
      observedDataUpdated() {
        return this.pubSub.asyncIterator('observedDataUpdated');
      }
    
      @Subscription(() => String, { name: 'observedDataDeleted' })
      observedDataDeleted() {
        return this.pubSub.asyncIterator('observedDataDeleted');
      }
    
  

  @Mutation(() => ObservedData)
  async createObservedData(
    @Args('input') createObservedDataInput: CreateObservedDataInput,
  ): Promise<ObservedData> {
    return this.observedDataService.create(createObservedDataInput);
  }

  @Query(() => ObservedDataSearchResult)
  async searchObservedData(
    @Args('filters', { type: () => SearchObservedDataInput, nullable: true }) filters: SearchObservedDataInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<ObservedDataSearchResult> {
    return this.observedDataService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => ObservedData, { nullable: true })
  async observedData(@Args('id') id: string): Promise<ObservedData> {
    return this.observedDataService.findOne(id);
  }

  @Mutation(() => ObservedData)
  async updateObservedData(
    @Args('id') id: string,
    @Args('input') updateObservedDataInput: UpdateObservedDataInput,
  ): Promise<ObservedData> {
    return this.observedDataService.update(id, updateObservedDataInput);
  }

  @Mutation(() => Boolean)
  async deleteObservedData(@Args('id') id: string): Promise<boolean> {
    return this.observedDataService.remove(id);
  }
}