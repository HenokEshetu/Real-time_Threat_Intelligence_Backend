import { Resolver, Query, Mutation, Args, Int,  Subscription,  } from '@nestjs/graphql';
import { IndicatorService } from './indicator.service';
import { Indicator } from './indicator.entity';
import { CreateIndicatorInput, UpdateIndicatorInput, SearchIndicatorInput, IndicatorSearchResult } from './indicator.input';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';


@Resolver(() => Indicator)
export class IndicatorResolver {
  
  constructor(
    private readonly indicatorService: IndicatorService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) {}

  // Date conversion helper
  public convertDates(payload: any): Indicator {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => Indicator, {
    name: 'indicatorCreated',
    resolve: (payload) => payload,
  })
  indicatorCreated() {
    return this.pubSub.asyncIterator('indicatorCreated');
  }

  @Subscription(() => Indicator, {
    name: 'indicatorUpdated',
    resolve: (payload) => payload,
  })
  indicatorUpdated() {
    return this.pubSub.asyncIterator('indicatorUpdated');
  }

  @Subscription(() => String, { name: 'indicatorDeleted' })
  indicatorDeleted() {
    return this.pubSub.asyncIterator('indicatorDeleted');
  }

  
  @Mutation(() => Indicator)
  async createIndicator(@Args('input') createIndicatorInput: CreateIndicatorInput): Promise<Indicator> {
    return this.indicatorService.create(createIndicatorInput);
  }

  @Query(() => IndicatorSearchResult)
  async searchIndicators(
    @Args('filters', { type: () => SearchIndicatorInput, nullable: true }) filters: SearchIndicatorInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IndicatorSearchResult> {
    return this.indicatorService.searchWithFilters(filters, page, pageSize);
  }
  
  @Query(() => Indicator, { nullable: true })
  async indicator(@Args('id') id: string): Promise<Indicator> {
    return this.indicatorService.findOne(id);
  }

  @Mutation(() => Indicator)
  async updateIndicator(
    @Args('id') id: string,
    @Args('input') updateIndicatorInput: UpdateIndicatorInput,
  ): Promise<Indicator> {
    return this.indicatorService.update(id, updateIndicatorInput);
  }

  @Mutation(() => Boolean)
  async deleteIndicator(@Args('id') id: string): Promise<boolean> {
    return this.indicatorService.remove(id);
  }

}

export { SearchIndicatorInput };
