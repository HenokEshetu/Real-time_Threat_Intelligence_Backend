import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { LocationService } from './location.service';
import { Location } from './location.entity';
import { CreateLocationInput, UpdateLocationInput } from './location.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchLocationInput extends PartialType(CreateLocationInput) { }
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
export class LocationResolver {
  
  constructor(
    private readonly locationService: LocationService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): Location {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => Location, {
    name: 'locationCreated',
    resolve: (payload) => payload,
  })
  locationCreated() {
    return this.pubSub.asyncIterator('locationCreated');
  }

  @Subscription(() => Location, {
    name: 'locationUpdated',
    resolve: (payload) => payload,
  })
  locationUpdated() {
    return this.pubSub.asyncIterator('locationUpdated');
  }

  @Subscription(() => String, { name: 'locationDeleted' })
  locationDeleted() {
    return this.pubSub.asyncIterator('locationDeleted');
  }

  @Mutation(() => Location)
  async createLocation(
    @Args('input') createLocationInput: CreateLocationInput,
  ): Promise<Location> {
    return this.locationService.create(createLocationInput);
  }

  @Query(() => LocationSearchResult)
  async searchLocations(
    @Args('filters', { type: () => SearchLocationInput, nullable: true }) filters: SearchLocationInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<LocationSearchResult> {
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