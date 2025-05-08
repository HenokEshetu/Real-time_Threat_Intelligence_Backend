import { Resolver, Query, Mutation, Args, Int } from '@nestjs/graphql';
import { MarkingDefinitionService } from './marking-definition.service';
import {
  CreateMarkingDefinitionInput,
  UpdateMarkingDefinitionInput,
  SearchMarkingDefinitionInput,
} from './marking-definition.input';
import { MarkingDefinition, MarkingDefinitionSearchResult } from './marking-definition.entity';
import { BaseStixResolver } from '../base-stix.resolver';

@Resolver(() => MarkingDefinition)
export class MarkingDefinitionResolver extends BaseStixResolver(MarkingDefinition) {
  public typeName = 'marking-definition';
  
  constructor(private readonly markingDefinitionService: MarkingDefinitionService) {
    super()
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