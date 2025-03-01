import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { ObservedDataService } from './observed-data.service';
import { ObservedData } from './observed-data.entity';
import { CreateObservedDataInput, UpdateObservedDataInput } from './observed-data.input';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchObservedDataInput extends PartialType(CreateObservedDataInput){}





@Resolver(() => ObservedData)
export class ObservedDataResolver {
  constructor(private readonly observedDataService: ObservedDataService) {}

  @Mutation(() => ObservedData)
  async createObservedData(@Args('input') input: CreateObservedDataInput): Promise<ObservedData> {
    return this.observedDataService.create(input);
  }

  @Query(() => [ObservedData])
  @Query(() => [ObservedData])
    async searchNotesWithFilters(
      @Args('filters', { type: () => SearchObservedDataInput, nullable: true }) filters?: Partial<SearchObservedDataInput>,
      @Args('page', { type: () => Number, nullable: true, defaultValue: 1 }) page?: number,
      @Args('pageSize', { type: () => Number, nullable: true, defaultValue: 10 }) pageSize?: number,
    ): Promise<ObservedData[]> {
      const result = await this.observedDataService.searchObservedDataWithFilters(filters, page, pageSize);
      return result.results;
    }

  @Query(() => ObservedData, { nullable: true })
  async getObservedData(@Args('id', { type: () => String }) id: string): Promise<ObservedData> {
    return this.observedDataService.findOne(id);
  }

  @Mutation(() => ObservedData)
  async updateObservedData(
    @Args('id', { type: () => String }) id: string,
    @Args('input') input: UpdateObservedDataInput,
  ): Promise<ObservedData> {
    return this.observedDataService.update(id, input);
  }

  @Mutation(() => Boolean)
  async removeObservedData(@Args('id', { type: () => String }) id: string): Promise<boolean> {
    return this.observedDataService.remove(id);
  }
}
