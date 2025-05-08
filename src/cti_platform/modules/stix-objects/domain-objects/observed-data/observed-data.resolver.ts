import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { ObservedDataService } from './observed-data.service';
import { ObservedData } from './observed-data.entity';
import { CreateObservedDataInput, UpdateObservedDataInput } from './observed-data.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

@InputType()
export class SearchObservedDataInput extends PartialType(CreateObservedDataInput){}


@ObjectType()
export class ObservedDataSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [ObservedData])
  results: ObservedData[];
}

@Resolver(() => ObservedData)
export class ObservedDataResolver extends BaseStixResolver(ObservedData) {
  public typeName = 'observed-data';
  
  constructor(private readonly observedDataService: ObservedDataService) {
    super()
  }

  @Mutation(() => ObservedData)
  async createObservedData(
    @Args('input') createObservedDataInput: CreateObservedDataInput,
  ): Promise<ObservedData> {
    return this.observedDataService.create(createObservedDataInput);
  }

  @Query(() => ObservedDataSearchResult)
  async searchObservedData(
    @Args('filters', { type: () => SearchObservedDataInput, nullable: true }) filters: SearchObservedDataInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<ObservedDataSearchResult> {
    return this.observedDataService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => ObservedData, { nullable: true })
  async observedData(@Args('id') id: string): Promise<ObservedData> {
    return this.observedDataService.findOne(id);
  }

  @Mutation(() => ObservedData)
  async updateObservedData(
    @Args('id') id: string,
    @Args('input') updateObservedDataInput: UpdateObservedDataInput,
  ): Promise<ObservedData> {
    return this.observedDataService.update(id, updateObservedDataInput);
  }

  @Mutation(() => Boolean)
  async deleteObservedData(@Args('id') id: string): Promise<boolean> {
    return this.observedDataService.remove(id);
  }
}