import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { ToolService } from './tool.service';
import { Tool } from './tool.entity';
import { CreateToolInput, UpdateToolInput } from './tool.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';

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
export class ToolResolver {
  constructor(private readonly toolService: ToolService) {}

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