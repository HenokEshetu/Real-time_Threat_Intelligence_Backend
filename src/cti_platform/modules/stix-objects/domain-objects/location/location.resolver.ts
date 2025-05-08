import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { LocationService } from './location.service';
import { Location } from './location.entity';
import { CreateLocationInput, UpdateLocationInput } from './location.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
@InputType()
export class SearchLocationInput extends PartialType(CreateLocationInput){}
@ObjectType()
export class LocationSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Location])
  results: Location[];
}

@Resolver(() => Location)
export class LocationResolver extends BaseStixResolver(Location) {
  public typeName = 'location';
  constructor(private readonly locationService: LocationService) {
    super()
  }

  @Mutation(() => Location)
  async createLocation(
    @Args('input') createLocationInput: CreateLocationInput,
  ): Promise<Location> {
    return this.locationService.create(createLocationInput);
  }

  @Query(() =>  LocationSearchResult)
  async searchLocations(
    @Args('filters', { type: () => SearchLocationInput, nullable: true }) filters: SearchLocationInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise< LocationSearchResult> {
    return this.locationService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Location, { nullable: true })
  async location(@Args('id') id: string): Promise<Location> {
    return this.locationService.findOne(id);
  }

  @Mutation(() => Location)
  async updateLocation(
    @Args('id') id: string,
    @Args('input') updateLocationInput: UpdateLocationInput,
  ): Promise<Location> {
    return this.locationService.update(id, updateLocationInput);
  }

  @Mutation(() => Boolean)
  async deleteLocation(@Args('id') id: string): Promise<boolean> {
    return this.locationService.remove(id);
  }
}