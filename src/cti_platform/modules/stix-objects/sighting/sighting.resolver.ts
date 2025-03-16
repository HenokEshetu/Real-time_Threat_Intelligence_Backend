import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { SightingService } from './sighting.service';
import { Sighting } from './sighting.entity';
import { CreateSightingInput, UpdateSightingInput } from './sighting.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchSightingInput extends PartialType(CreateSightingInput){}

@ObjectType()
export class SightingSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Sighting])
  results: Sighting[];
}

@Resolver(() => Sighting)
export class SightingResolver {
  constructor(private readonly sightingService: SightingService) {}

  @Mutation(() => Sighting)
  async createSighting(
    @Args('input') createSightingInput: CreateSightingInput,
  ): Promise<Sighting> {
    return this.sightingService.create(createSightingInput);
  }

  @Query(() => SightingSearchResult)
  async searchSightings(
    @Args('filters', { type: () => SearchSightingInput, nullable: true }) filters: SearchSightingInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<SightingSearchResult> {
    return this.sightingService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Sighting, { nullable: true })
  async sighting(@Args('id') id: string): Promise<Sighting> {
    return this.sightingService.findOne(id);
  }

  @Mutation(() => Sighting)
  async updateSighting(
    @Args('id') id: string,
    @Args('input') updateSightingInput: UpdateSightingInput,
  ): Promise<Sighting> {
    return this.sightingService.update(id, updateSightingInput);
  }

  @Mutation(() => Boolean)
  async deleteSighting(@Args('id') id: string): Promise<boolean> {
    return this.sightingService.remove(id);
  }
}