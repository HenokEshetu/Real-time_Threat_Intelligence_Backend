import { Resolver, Query, InputType, Mutation, Args, Int, ObjectType, Field, PartialType } from '@nestjs/graphql';
import { ThreatActor } from './threat-actor.entity';
import { CreateThreatActorInput, UpdateThreatActorInput } from './threat-actor.input';
import { ThreatActorType } from '../../../../core/types/common-data-types';

@InputType()
export class SearchThreatActorInput extends PartialType(CreateThreatActorInput) {}

@ObjectType()
export class ThreatActorSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [ThreatActor])
  results: ThreatActor[];
}

// Mock data store
const MOCK_THREAT_ACTORS: ThreatActor[] = [
  {
    id: '1',
    type: 'threat-actor',
    threat_actor_types: [ThreatActorType.SPY],
    spec_version: '2.1',
    created: new Date('2014-01-01T00:00:00Z').toISOString(),
    modified: new Date('2023-01-01T00:00:00Z').toISOString(),
    name: 'APT28',
    description: 'A Russian cyber espionage group.',
    roles: ['SPY'],
    sophistication: 'ADVANCED',
    resource_level: 'NATION_STATE',
    primary_motivation: 'POLITICAL',
    aliases: ['Fancy Bear'],
    labels: ['russian', 'apt'],
    first_seen: new Date('2014-01-01T00:00:00Z'),
    last_seen: new Date('2023-01-01T00:00:00Z'),
  },
  {
    id: '2',
    type: 'threat-actor',
    threat_actor_types: [ThreatActorType.CRIME_SYNDICATE],
    spec_version: '2.1',
    created: new Date('2010-01-01T00:00:00Z').toISOString(),
    modified: new Date('2022-12-31T00:00:00Z').toISOString(),
    name: 'Lazarus Group',
    description: 'A North Korean threat actor.',
    roles: ['CRIME_SYNDICATE'],
    sophistication: 'EXPERT',
    resource_level: 'NATION_STATE',
    primary_motivation: 'FINANCIAL',
    aliases: ['Hidden Cobra'],
    labels: ['north-korea', 'apt'],
    first_seen: new Date('2010-01-01T00:00:00Z'),
    last_seen: new Date('2022-12-31T00:00:00Z'),
  },
];

let threatActors = [...MOCK_THREAT_ACTORS];

@Resolver(() => ThreatActor)
export class ThreatActorResolver {
  // No service, using mock data

  @Mutation(() => ThreatActor)
  async createThreatActor(
    @Args('input') createThreatActorInput: CreateThreatActorInput,
  ): Promise<ThreatActor> {
    const newActor: ThreatActor = {
      id: (threatActors.length + 1).toString(),
      ...createThreatActorInput,
      first_seen: createThreatActorInput.first_seen ? new Date(createThreatActorInput.first_seen) : undefined,
      last_seen: createThreatActorInput.last_seen ? new Date(createThreatActorInput.last_seen) : undefined,
    };
    threatActors.push(newActor);
    return newActor;
  }

  @Query(() => ThreatActorSearchResult)
  async searchThreatActors(
    @Args('filters', { type: () => SearchThreatActorInput, nullable: true }) filters: SearchThreatActorInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<ThreatActorSearchResult> {
    // Simple filter logic (extend as needed)
    let filtered = threatActors;
    if (filters && filters.name) {
      filtered = filtered.filter(actor =>
        actor.name.toLowerCase().includes(filters.name.toLowerCase())
      );
    }
    const total = filtered.length;
    const start = (page - 1) * pageSize;
    const end = start + pageSize;
    const results = filtered.slice(start, end).map(actor => ({
      ...actor,
      first_seen: actor.first_seen ? new Date(actor.first_seen) : undefined,
      last_seen: actor.last_seen ? new Date(actor.last_seen) : undefined,
    }));
    return {
      page,
      pageSize,
      total,
      totalPages: Math.ceil(total / pageSize),
      results,
    };
  }

  @Query(() => ThreatActor, { nullable: true })
  async threatActor(@Args('id') id: string): Promise<ThreatActor | undefined> {
    const actor = threatActors.find(actor => actor.id === id);
    return actor
      ? {
          ...actor,
          first_seen: actor.first_seen ? new Date(actor.first_seen) : undefined,
          last_seen: actor.last_seen ? new Date(actor.last_seen) : undefined,
        }
      : undefined;
  }

  @Mutation(() => ThreatActor)
  async updateThreatActor(
    @Args('id') id: string,
    @Args('input', { type: () => UpdateThreatActorInput }) updateThreatActorInput: UpdateThreatActorInput,
  ): Promise<ThreatActor> {
    const idx = threatActors.findIndex(actor => actor.id === id);
    if (idx === -1) throw new Error('ThreatActor not found');
    threatActors[idx] = {
      ...threatActors[idx],
      ...updateThreatActorInput,
      first_seen: updateThreatActorInput.first_seen
        ? new Date(updateThreatActorInput.first_seen)
        : threatActors[idx].first_seen,
      last_seen: updateThreatActorInput.last_seen
        ? new Date(updateThreatActorInput.last_seen)
        : threatActors[idx].last_seen,
    };
    return threatActors[idx];
  }

  @Mutation(() => Boolean)
  async deleteThreatActor(@Args('id') id: string): Promise<boolean> {
    const idx = threatActors.findIndex(actor => actor.id === id);
    if (idx === -1) return false;
    threatActors.splice(idx, 1);
    return true;
  }
}