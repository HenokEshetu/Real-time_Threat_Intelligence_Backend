import { Resolver, InputType, Query, Mutation, Args } from '@nestjs/graphql';
import { GroupingService } from './grouping.service';
import { Grouping } from './grouping.entity';
import { CreateGroupingInput, UpdateGroupingInput } from './grouping.input';
import { NotFoundException } from '@nestjs/common';

import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchGroupingInput extends PartialType(CreateGroupingInput){}

@Resolver('Grouping')
export class GroupingResolver {
  constructor(private readonly GroupingService: GroupingService) {}

  //  Create a new Course of Action
  @Mutation(() => Grouping )
  async createGrouping(
    @Args('createGroupingInput') createGroupingInput: CreateGroupingInput,
  ): Promise<string> {
    const grouping = await this.GroupingService.create(createGroupingInput);
    return grouping.id;
  }

  //  Get a Course of Action by ID
  @Query(() => Grouping , { nullable: true })
  async getGrouping(@Args('id') id: string): Promise<any> {
    const grouping = await this.GroupingService.findOne(id);
    if (!grouping) {
      throw new NotFoundException(`Course of Action with ID ${id} not found.`);
    }
    return grouping;
  }

  //  Update a Course of Action
  @Mutation(() => Grouping )
  async updateGrouping(
    @Args('id') id: string,
    @Args('updateGroupingInput') updateGroupingInput: UpdateGroupingInput,
  ): Promise<any> {
    return this.GroupingService.update(id, updateGroupingInput);
  }

  //  Delete a Course of Action
  @Mutation(() => Boolean)
  async removeGrouping(@Args('id') id: string): Promise<boolean> {
    return this.GroupingService.remove(id);
  }

  //  Search Course of Actions with filters
  @Query(() => Grouping )
  async searchGrouping(
    @Args('filters', { type: () => SearchGroupingInput, nullable: true }) filters: Partial<SearchGroupingInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number,
  ): Promise<any> {
    return this.GroupingService.searchWithFilters(filters, page, pageSize);
  }
}