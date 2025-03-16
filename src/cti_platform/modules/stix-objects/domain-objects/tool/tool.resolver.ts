import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { ToolService } from './tool.service';
import { Tool } from './tool.entity';
import { CreateToolInput, UpdateToolInput } from './tool.input';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchToolInput extends PartialType(CreateToolInput){}



@Resolver(() => Tool)
export class ToolResolver {
  constructor(private readonly toolService: ToolService) {}

  //  Create a new tool
  @Mutation(() => Tool)
  async createTool(@Args('createToolInput') createToolInput: CreateToolInput): Promise<Tool> {
    return this.toolService.create(createToolInput);
  }

  //  Find tool by ID
  @Query(() => Tool, { nullable: true })
  async getTool(@Args('id') id: string): Promise<Tool> {
    return this.toolService.findOne(id);
  }

  //  Update a tool
  @Mutation(() => Tool)
  async updateTool(
    @Args('id') id: string,
    @Args('updateToolInput') updateToolInput: UpdateToolInput,
  ): Promise<Tool> {
    return this.toolService.update(id, updateToolInput);
  }

  //  Delete a tool
  @Mutation(() => Boolean)
  async removeTool(@Args('id') id: string): Promise<boolean> {
    return this.toolService.remove(id);
  }

  //  Search tools with filters
  @Query(() => [Tool])
  async searchTools(
    @Args('filters', { type: () => SearchToolInput, nullable: true }) filters?: Partial<SearchToolInput>,
    @Args('page', { type: () => Number, nullable: true }) page = 1,
    @Args('pageSize', { type: () => Number, nullable: true }) pageSize = 10,
  ): Promise<{ total: number; page: number; pageSize: number; results: Tool[] }> {
    return this.toolService.searchToolWithFilters(filters, page, pageSize);
  }
}
