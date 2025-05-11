import { Resolver, Query, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { MarkingDefinitionService } from './marking-definition.service';
import {
  CreateMarkingDefinitionInput,
  UpdateMarkingDefinitionInput,
  SearchMarkingDefinitionInput,
} from './marking-definition.input';
import { MarkingDefinition, MarkingDefinitionSearchResult } from './marking-definition.entity';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from '../../pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';


@Resolver(() => MarkingDefinition)
export class MarkingDefinitionResolver {

  constructor(private readonly markingDefinitionService: MarkingDefinitionService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }
  // Date conversion helper
  public convertDates(payload: any): MarkingDefinition {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => MarkingDefinition, {
    name: 'markingdefinitionCreated',
    resolve: (payload) => payload,
  })
  markingdefinitionCreated() {
    return this.pubSub.asyncIterator('markingdefinitionCreated');
  }
  @Subscription(() => MarkingDefinition, {
    name: 'markingdefinitionUpdated',
    resolve: (payload) => payload,
  })
  markingdefinitionUpdated() {
    return this.pubSub.asyncIterator('markingdefinitionUpdated');
  }
  @Subscription(() => String, { name: 'markingdefinitionDeleted' })
  markingdefinitionDeleted() {
    return this.pubSub.asyncIterator('markingdefinitionDeleted');
  }

  @Mutation(() => MarkingDefinition)
  async createMarkingDefinition(
    @Args('input') createMarkingDefinitionInput: CreateMarkingDefinitionInput,
  ): Promise<MarkingDefinition> {
    return this.markingDefinitionService.create(createMarkingDefinitionInput);
  }

  @Query(() => MarkingDefinitionSearchResult)
  async searchMarkingDefinitions(
    @Args('filters', { type: () => SearchMarkingDefinitionInput, nullable: true })
    filters: SearchMarkingDefinitionInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<MarkingDefinitionSearchResult> {
    return this.markingDefinitionService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => MarkingDefinition, { nullable: true })
  async markingDefinition(@Args('id') id: string): Promise<MarkingDefinition> {
    return this.markingDefinitionService.findOne(id);
  }

  @Mutation(() => MarkingDefinition)
  async updateMarkingDefinition(
    @Args('id') id: string,
    @Args('input') updateMarkingDefinitionInput: UpdateMarkingDefinitionInput,
  ): Promise<MarkingDefinition> {
    return this.markingDefinitionService.update(id, updateMarkingDefinitionInput);
  }

  @Mutation(() => Boolean)
  async deleteMarkingDefinition(@Args('id') id: string): Promise<boolean> {
    return this.markingDefinitionService.remove(id);
  }
}