import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { OpinionService } from './opinion.service';
import { Opinion } from './opinion.entity';
import { CreateOpinionInput, UpdateOpinionInput } from './opinion.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';

@InputType()
export class SearchOpinionInput extends PartialType(CreateOpinionInput){}

@ObjectType()
export class  OpinionSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Opinion])
  results: Opinion[];
}

@Resolver(() => Opinion)
export class OpinionResolver {
  constructor(private readonly opinionService: OpinionService) {}

  @Mutation(() => Opinion)
  async createOpinion(
    @Args('input') createOpinionInput: CreateOpinionInput,
  ): Promise<Opinion> {
    return this.opinionService.create(createOpinionInput);
  }

  @Query(() => OpinionSearchResult)
  async searchOpinions(
    @Args('filters', { type: () => SearchOpinionInput, nullable: true }) filters: SearchOpinionInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
    @Args('sortField', { type: () => String, nullable: true }) sortField?: keyof Opinion,
    @Args('sortOrder', { type: () => String, defaultValue: 'desc' }) sortOrder: 'asc' | 'desc' = 'desc',
    @Args('fullTextSearch', { type: () => String, nullable: true }) fullTextSearch?: string,
  ): Promise<OpinionSearchResult> {
    return this.opinionService.searchWithFilters(filters, page, pageSize, sortField, sortOrder, fullTextSearch);
  }

  @Query(() => Opinion, { nullable: true })
  async opinion(@Args('id') id: string): Promise<Opinion> {
    return this.opinionService.findOne(id);
  }

  @Mutation(() => Opinion)
  async updateOpinion(
    @Args('id') id: string,
    @Args('input') updateOpinionInput: UpdateOpinionInput,
  ): Promise<Opinion> {
    return this.opinionService.update(id, updateOpinionInput);
  }

  @Mutation(() => Boolean)
  async deleteOpinion(@Args('id') id: string): Promise<boolean> {
    return this.opinionService.remove(id);
  }
}