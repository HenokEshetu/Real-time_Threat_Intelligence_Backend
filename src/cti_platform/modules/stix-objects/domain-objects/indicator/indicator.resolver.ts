import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { IndicatorService } from './indicator.service';
import { Indicator } from './indicator.entity';
import { CreateIndicatorInput, UpdateIndicatorInput } from './indicator.input';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchIndicatorInput extends PartialType(CreateIndicatorInput){}




@Resolver(() => Indicator)
export class IndicatorResolver {
  constructor(private readonly indicatorService: IndicatorService) {}

  @Mutation(() => Indicator)
  async createIndicator(@Args('createIndicatorInput') createIndicatorInput: CreateIndicatorInput): Promise<Indicator> {
    return this.indicatorService.create(createIndicatorInput);
  }

  @Query(() => Indicator, { nullable: true })
  async getIndicator(@Args('id') id: string): Promise<Indicator> {
    return this.indicatorService.findOne(id);
  }

  @Mutation(() => Indicator)
  async updateIndicator(
    @Args('id') id: string,
    @Args('updateIndicatorInput') updateIndicatorInput: UpdateIndicatorInput
  ): Promise<Indicator> {
    return this.indicatorService.update(id, updateIndicatorInput);
  }

  @Mutation(() => Boolean)
  async removeIndicator(@Args('id') id: string): Promise<boolean> {
    return this.indicatorService.remove(id);
  }

  @Query(() => [Indicator])
  async searchIndicators(
    @Args('filters', { type: () => SearchIndicatorInput, nullable: true }) filters?: Partial<SearchIndicatorInput>,
    @Args('page', { type: () => Number, nullable: true, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, nullable: true, defaultValue: 10 }) pageSize?: number
  ): Promise<{ total: number; page: number; pageSize: number; results: Indicator[] }> {
    return this.indicatorService.searchIndicatorWithFilters(filters, page, pageSize);
  }
}
