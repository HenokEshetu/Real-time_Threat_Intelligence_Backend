import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { LocationService } from './location.service';
import { Location } from './location.entity';
import { CreateLocationInput, UpdateLocationInput } from './location.input';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchLocationInput extends PartialType(CreateLocationInput){}




@Resolver(() => Location)
export class LocationResolver {
  constructor(private readonly locationService: LocationService) {}

  // Mutation to create a location
  @Mutation(() => Location)
  async createLocation(@Args('createLocationInput') createLocationInput: CreateLocationInput): Promise<Location> {
    return this.locationService.create(createLocationInput);
  }

  // Query to fetch a location by ID
  @Query(() => Location, { nullable: true })
  async getLocation(@Args('id') id: string): Promise<Location> {
    return this.locationService.findOne(id);
  }

  // Mutation to update a location
  @Mutation(() => Location)
  async updateLocation(
    @Args('id') id: string,
    @Args('updateLocationInput') updateLocationInput: UpdateLocationInput
  ): Promise<Location> {
    return this.locationService.update(id, updateLocationInput);
  }

  // Mutation to delete a location
  @Mutation(() => Boolean)
  async removeLocation(@Args('id') id: string): Promise<boolean> {
    return this.locationService.remove(id);
  }

  // Query to search locations with filters
  @Query(() => [Location])
async searchLocations(
  @Args('filters', { type: () => SearchLocationInput, nullable: true }) filters?: SearchLocationInput,
  @Args('page', { type: () => Number, nullable: true, defaultValue: 1 }) page?: number,
  @Args('pageSize', { type: () => Number, nullable: true, defaultValue: 10 }) pageSize?: number,
): Promise<Location[]> {
  return this.locationService.searchLocationWithFilters(filters, page, pageSize);
}

}
