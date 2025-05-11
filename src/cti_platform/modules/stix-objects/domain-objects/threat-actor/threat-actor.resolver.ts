import { Resolver, Query,InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { ThreatActorService } from './threat-actor.service';
import { ThreatActor } from './threat-actor.entity';
import { CreateThreatActorInput, UpdateThreatActorInput } from './threat-actor.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchThreatActorInput extends PartialType(CreateThreatActorInput){}

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

@Resolver(() => ThreatActor)
export class ThreatActorResolver {
  
  constructor(
        private readonly threatActorService: ThreatActorService,
        @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
      ) { }
    
      // Date conversion helper
      public convertDates(payload: any): ThreatActor {
        const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
        dateFields.forEach(field => {
          if (payload[field]) payload[field] = new Date(payload[field]);
        });
        return payload;
      }
    
      // Subscription Definitions
      @Subscription(() => ThreatActor, {
        name: 'threatActorCreated',
        resolve: (payload) => payload,
      })
      threatactorCreated() {
        return this.pubSub.asyncIterator('threatActorCreated');
      }
    
      @Subscription(() => ThreatActor, {
        name: 'threatActorUpdated',
        resolve: (payload) => payload,
      })
      threatactorUpdated() {
        return this.pubSub.asyncIterator('threatActorUpdated');
      }
    
      @Subscription(() => String, { name: 'threatActorDeleted' })
      threatactorDeleted() {
        return this.pubSub.asyncIterator('threatActorDeleted');
      }

  @Mutation(() => ThreatActor)
  async createThreatActor(
    @Args('input') createThreatActorInput: CreateThreatActorInput,
  ): Promise<ThreatActor> {
    return this.threatActorService.create(createThreatActorInput);
  }

  @Query(() => ThreatActorSearchResult)
  async searchThreatActors(
    @Args('filters', { type: () => SearchThreatActorInput, nullable: true }) filters: SearchThreatActorInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<ThreatActorSearchResult> {
    return this.threatActorService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => ThreatActor, { nullable: true })
  async threatActor(@Args('id') id: string): Promise<ThreatActor> {
    return this.threatActorService.findOne(id);
  }

  @Mutation(() => ThreatActor)
  async updateThreatActor(
    @Args('id') id: string,
    @Args('input') updateThreatActorInput: UpdateThreatActorInput,
  ): Promise<ThreatActor> {
    return this.threatActorService.update(id, updateThreatActorInput);
  }

  @Mutation(() => Boolean)
  async deleteThreatActor(@Args('id') id: string): Promise<boolean> {
    return this.threatActorService.remove(id);
  }
}