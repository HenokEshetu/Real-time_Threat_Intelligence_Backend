import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { OpinionService } from './opinion.service';
import { Opinion } from './opinion.entity';
import { CreateOpinionInput, UpdateOpinionInput } from './opinion.input';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchOpinionInput extends PartialType(CreateOpinionInput){}



@Resolver(() => Opinion)
export class OpinionResolver {
  constructor(private readonly opinionService: OpinionService) {}

  @Mutation(() => Opinion)
  async createOpinion(@Args('input') input: CreateOpinionInput): Promise<Opinion> {
    return this.opinionService.create(input);
  }

  @Query(() => [Opinion])
  async searchOpinionWithDynamicFilters(
    @Args('filters', { type: () => SearchOpinionInput, nullable: true }) filters?: Partial<SearchOpinionInput>,
    @Args('page', { type: () => Number, nullable: true, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, nullable: true, defaultValue: 10 }) pageSize?: number,
  ): Promise<Opinion[]> {
    const results = await this.opinionService.searchOpinionWithDynamicFilters(filters, page, pageSize);
    return results.map((result) => new Opinion()); // Ensure the result is properly mapped
  }

  @Query(() => Opinion, { nullable: true })
  async getOpinion(@Args('id', { type: () => String }) id: string): Promise<Opinion | null> {
    return this.opinionService.findOne(id);
  }

  @Mutation(() => Opinion)
  async updateOpinion(
    @Args('id', { type: () => String }) id: string,
    @Args('input') input: UpdateOpinionInput,
  ): Promise<Opinion> {
    return this.opinionService.update(id, input);
  }

  @Mutation(() => Boolean)
  async removeOpinion(@Args('id', { type: () => String }) id: string): Promise<boolean> {
    return this.opinionService.remove(id);
  }
}
