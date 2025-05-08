import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { IntrusionSetService } from './intrusion-set.service';
import { CreateIntrusionSetInput, UpdateIntrusionSetInput } from './intrusion-set.input';
import { IntrusionSet } from './intrusion-set.entity';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
@InputType()
export class SearchIntrusionSetInput extends PartialType(CreateIntrusionSetInput){}

@ObjectType()
export class IntrusionSetSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [IntrusionSet])
  results: IntrusionSet[];
}

@Resolver(() => IntrusionSet)
export class IntrusionSetResolver extends BaseStixResolver(IntrusionSet) {
  public typeName = 'intrusion-set';
  constructor(private readonly intrusionSetService: IntrusionSetService) {
    super()
  }

  @Mutation(() => IntrusionSet)
  async createIntrusionSet(
    @Args('input') createIntrusionSetInput: CreateIntrusionSetInput,
  ): Promise<IntrusionSet> {
    return this.intrusionSetService.create(createIntrusionSetInput);
  }

  @Query(() => IntrusionSetSearchResult)
  async searchIntrusionSets(
    @Args('filters', { type: () => SearchIntrusionSetInput, nullable: true }) filters: SearchIntrusionSetInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IntrusionSetSearchResult> {
    return this.intrusionSetService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => IntrusionSet, { nullable: true })
  async intrusionSet(@Args('id') id: string): Promise<IntrusionSet> {
    return this.intrusionSetService.findOne(id);
  }

  @Mutation(() => IntrusionSet)
  async updateIntrusionSet(
    @Args('id') id: string,
    @Args('input') updateIntrusionSetInput: UpdateIntrusionSetInput,
  ): Promise<IntrusionSet> {
    return this.intrusionSetService.update(id, updateIntrusionSetInput);
  }

  @Mutation(() => Boolean)
  async deleteIntrusionSet(@Args('id') id: string): Promise<boolean> {
    return this.intrusionSetService.remove(id);
  }
}