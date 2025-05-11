import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { InfrastructureService } from './infrastructure.service';
import { Infrastructure } from './infrastructure.entity';
import { CreateInfrastructureInput, UpdateInfrastructureInput } from './infrastructure.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchInfrastructureInput extends PartialType(CreateInfrastructureInput) { }


@ObjectType()
export class InfrastructureSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Infrastructure])
  results: Infrastructure[];
}

@Resolver(() => Infrastructure)
export class InfrastructureResolver  {
  constructor(
    private readonly infrastructureService: InfrastructureService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): Infrastructure {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => Infrastructure, {
    name: 'infrastructureCreated',
    resolve: (payload) => payload,
  })
  infrastructureCreated() {
    return this.pubSub.asyncIterator('infrastructureCreated');
  }

  @Subscription(() => Infrastructure, {
    name: 'infrastructureUpdated',
    resolve: (payload) => payload,
  })
  infrastructureUpdated() {
    return this.pubSub.asyncIterator('infrastructureUpdated');
  }

  @Subscription(() => String, { name: 'infrastructureDeleted' })
  infrastructureDeleted() {
    return this.pubSub.asyncIterator('infrastructureDeleted');
  }

  @Mutation(() => Infrastructure)
  async createInfrastructure(
    @Args('input') createInfrastructureInput: CreateInfrastructureInput,
  ): Promise<Infrastructure> {
    return this.infrastructureService.create(createInfrastructureInput);
  }

  @Query(() => InfrastructureSearchResult)
  async searchInfrastructures(
    @Args('filters', { type: () => SearchInfrastructureInput, nullable: true }) filters: SearchInfrastructureInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<InfrastructureSearchResult> {
    return this.infrastructureService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Infrastructure, { nullable: true })
  async infrastructure(@Args('id') id: string): Promise<Infrastructure> {
    return this.infrastructureService.findOne(id);
  }

  @Mutation(() => Infrastructure)
  async updateInfrastructure(
    @Args('id') id: string,
    @Args('input') updateInfrastructureInput: UpdateInfrastructureInput,
  ): Promise<Infrastructure> {
    return this.infrastructureService.update(id, updateInfrastructureInput);
  }

  @Mutation(() => Boolean)
  async deleteInfrastructure(@Args('id') id: string): Promise<boolean> {
    return this.infrastructureService.remove(id);
  }
}