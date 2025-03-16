import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { ThreatActorService } from './threat-actor.service';
import { ThreatActor } from './threat-actor.entity';
import { CreateThreatActorInput, UpdateThreatActorInput } from './threat-actor.input';

import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchThreatActorInput extends PartialType(CreateThreatActorInput){}


@Resolver(() => ThreatActor)
export class ThreatActorResolver {
  constructor(private readonly threatActorService: ThreatActorService) {}

  // ✅ Create a new threat actor
  @Mutation(() => ThreatActor)
  async createThreatActor(@Args('input') input: CreateThreatActorInput): Promise<ThreatActor> {
    return this.threatActorService.create(input);
  }

  // ✅ Get a threat actor by ID
  @Query(() => ThreatActor, { nullable: true })
  async getThreatActor(@Args('id') id: string): Promise<ThreatActor> {
    return this.threatActorService.findOne(id);
  }

  // ✅ Update a threat actor
  @Mutation(() => ThreatActor)
  async updateThreatActor(
    @Args('id') id: string,
    @Args('input') input: UpdateThreatActorInput,
  ): Promise<ThreatActor> {
    return this.threatActorService.update(id, input);
  }

  // ✅ Delete a threat actor
  @Mutation(() => Boolean)
  async removeThreatActor(@Args('id') id: string): Promise<boolean> {
    return this.threatActorService.remove(id);
  }

  // ✅ Search threat actors with filters
  @Query(() => [ThreatActor])
  async searchThreatActors(
    @Args('filters', { type: () => SearchThreatActorInput, nullable: true }) filters?: Partial<SearchThreatActorInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number,
  ): Promise<ThreatActor[]> {
    const result = await this.threatActorService.searchThreatActorWithFilters(filters, page, pageSize);
    return result.results;
  }
}
