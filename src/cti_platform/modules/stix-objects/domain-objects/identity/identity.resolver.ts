import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { IdentityService } from './identity.service';
import { Identity } from './identity.entity';
import { CreateIdentityInput, UpdateIdentityInput } from './identity.input';
import { NotFoundException } from '@nestjs/common';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchIdentityInput extends PartialType(CreateIdentityInput){}


@Resolver('Identity')
export class IdentityResolver {
  constructor(private readonly identityService: IdentityService) {}

  //  Create a new Course of Action
  @Mutation(() => Identity )
  async createIdentity(
    @Args('createGroupingInput') createIdentityInput: CreateIdentityInput,
  ): Promise<string> {
    const grouping = await this.identityService.create(createIdentityInput);
    return grouping.id;
  }

  //  Get a Course of Action by ID
  @Query(() => Identity , { nullable: true })
  async getIdentity(@Args('id') id: string): Promise<any> {
    const grouping = await this.identityService.findOne(id);
    if (!grouping) {
      throw new NotFoundException(`Course of Action with ID ${id} not found.`);
    }
    return grouping;
  }

  //  Update a Course of Action
  @Mutation(() => Identity )
  async updateIdentity(
    @Args('id') id: string,
    @Args('updateIdentityInput') updateIdentityInput: UpdateIdentityInput,
  ): Promise<any> {
    return this.identityService.update(id, updateIdentityInput);
  }

  //  Delete a Course of Action
  @Mutation(() => Boolean)
  async removeIdentity(@Args('id') id: string): Promise<boolean> {
    return this.identityService.remove(id);
  }

  //  Search Course of Actions with filters
  @Query(() => Identity )
  async searchIdentity(
    @Args('filters', { type: () => SearchIdentityInput, nullable: true }) filters: Partial<SearchIdentityInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number,
  ): Promise<any> {
    return this.identityService.searchIdentityWithFilters(filters, page, pageSize);
  }
}