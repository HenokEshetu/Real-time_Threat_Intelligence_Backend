import { Resolver, Query,InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { ToolService } from './tool.service';
import { Tool } from './tool.entity';
import { CreateToolInput, UpdateToolInput } from './tool.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchToolInput extends PartialType(CreateToolInput){}


@ObjectType()
export class ToolSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Tool])
  results: Tool[];
}

@Resolver(() => Tool)
export class ToolResolver  {
    constructor(
      private readonly toolService: ToolService,
      @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
    ) { }
  
    // Date conversion helper
    public convertDates(payload: any): Tool {
      const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
      dateFields.forEach(field => {
        if (payload[field]) payload[field] = new Date(payload[field]);
      });
      return payload;
    }
  
    // Subscription Definitions
    @Subscription(() => Tool, {
      name: 'toolCreated',
      resolve: (payload) => payload,
    })
    toolCreated() {
      return this.pubSub.asyncIterator('toolCreated');
    }
  
    @Subscription(() => Tool, {
      name: 'toolUpdated',
      resolve: (payload) => payload,
    })
    toolUpdated() {
      return this.pubSub.asyncIterator('toolUpdated');
    }
    @Subscription(() => String, { name: 'toolDeleted' })
    toolDeleted() {
      return this.pubSub.asyncIterator('toolDeleted');
  
    }

  @Mutation(() => Tool)
  async createTool(
    @Args('input') createToolInput: CreateToolInput,
  ): Promise<Tool> {
    return this.toolService.create(createToolInput);
  }

  @Query(() => ToolSearchResult)
  async searchTools(
    @Args('filters', { type: () => SearchToolInput, nullable: true }) filters: SearchToolInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<ToolSearchResult> {
    return this.toolService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Tool, { nullable: true })
  async tool(@Args('id') id: string): Promise<Tool> {
    return this.toolService.findOne(id);
  }

  @Mutation(() => Tool)
  async updateTool(
    @Args('id') id: string,
    @Args('input') updateToolInput: UpdateToolInput,
  ): Promise<Tool> {
    return this.toolService.update(id, updateToolInput);
  }

  @Mutation(() => Boolean)
  async deleteTool(@Args('id') id: string): Promise<boolean> {
    return this.toolService.remove(id);
  }
}