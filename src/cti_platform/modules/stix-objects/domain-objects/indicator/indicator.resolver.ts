import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { IndicatorService } from './indicator.service';
import { Indicator } from './indicator.entity';
import { CreateIndicatorInput, UpdateIndicatorInput } from './indicator.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchIndicatorInput extends PartialType(CreateIndicatorInput){}

@ObjectType()
export class IndicatorSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Indicator])
  results: Indicator[];
}

@Resolver(() => Indicator)
export class IndicatorResolver {
  constructor(private readonly indicatorService: IndicatorService) {}

  @Mutation(() => Indicator)
  async createIndicator(
    @Args('input') createIndicatorInput: CreateIndicatorInput,
  ): Promise<Indicator> {
    return this.indicatorService.create(createIndicatorInput);
  }

  @Query(() => IndicatorSearchResult)
  async searchIndicators(
    @Args('filters', { type: () => SearchIndicatorInput, nullable: true }) filters: SearchIndicatorInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IndicatorSearchResult> {
    return this.indicatorService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Indicator, { nullable: true })
  async indicator(@Args('id') id: string): Promise<Indicator> {
    return this.indicatorService.findOne(id);
  }

  @Mutation(() => Indicator)
  async updateIndicator(
    @Args('id') id: string,
    @Args('input') updateIndicatorInput: UpdateIndicatorInput,
  ): Promise<Indicator> {
    return this.indicatorService.update(id, updateIndicatorInput);
  }

  @Mutation(() => Boolean)
  async deleteIndicator(@Args('id') id: string): Promise<boolean> {
    return this.indicatorService.remove(id);
  }
}