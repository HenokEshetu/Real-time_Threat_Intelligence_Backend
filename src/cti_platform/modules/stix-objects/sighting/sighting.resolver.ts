import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { SightingService } from './sighting.service';
import { Sighting } from './sighting.entity';
import { CreateSightingInput, UpdateSightingInput } from './sighting.input';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchSightingInput extends PartialType(CreateSightingInput){}




@Resolver(() => Sighting)
export class SightingResolver {
  constructor(private readonly sightingService: SightingService) {}

  //  Create a new sighting
  @Mutation(() => Sighting)
  async createSighting(@Args('input') input: CreateSightingInput): Promise<Sighting> {
    return this.sightingService.create(input);
  }

  //  Get a single sighting by ID
  @Query(() => Sighting, { nullable: true })
  async getSighting(@Args('id', { type: () => String }) id: string): Promise<Sighting> {
    return this.sightingService.findOne(id);
  }

  //  Update an existing sighting
  @Mutation(() => Sighting)
  async updateSighting(
    @Args('id', { type: () => String }) id: string,
    @Args('input') input: UpdateSightingInput,
  ): Promise<Sighting> {
    return this.sightingService.update(id, input);
  }

  //  Delete a sighting
  @Mutation(() => Boolean)
  async deleteSighting(@Args('id', { type: () => String }) id: string): Promise<boolean> {
    return this.sightingService.remove(id);
  }

  // Advanced search with filters
  @Query(() => [Sighting])
  async searchSightings(
    @Args('filters', { type: () => SearchSightingInput, nullable: true }) filters?: Partial<SearchSightingInput>,
    @Args('page', { type: () => Int, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize?: number,
  ): Promise<Sighting[]> {
    const result = await this.sightingService.searchSightingWithFilters(filters || {}, page, pageSize);
    return result.results;
  }
}
