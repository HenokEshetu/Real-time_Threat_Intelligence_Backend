import { Resolver,InputType, Query, Mutation, Int,ObjectType, Field, Args, Subscription, } from '@nestjs/graphql';
import { AutonomousSystemService } from './autonomous-system.service';
import { AutonomousSystem } from './autonomous-system.entity';
import { CreateAutonomousSystemInput, UpdateAutonomousSystemInput } from './autonomous-system.input';
import { PartialType } from '@nestjs/graphql';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
@InputType()
export class SearchAutonomousSystemInput extends PartialType(CreateAutonomousSystemInput) {}

@ObjectType()
export class AutonomousSystemSearchResult  {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [AutonomousSystem])
  results: AutonomousSystem[];
}

@Resolver(() => AutonomousSystem)
export class AutonomousSystemResolver {
  constructor(
          private readonly autonomousSystemService: AutonomousSystemService,
          @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
        ) {}
      
        // Date conversion helper
        public convertDates(payload: any): AutonomousSystem {
          const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
          dateFields.forEach(field => {
            if (payload[field]) payload[field] = new Date(payload[field]);
          });
          return payload;
        }
      
        // Subscription Definitions
        @Subscription(() => AutonomousSystem, {
          name: 'autonomousSystemCreated',
          resolve: (payload) => payload,
        })
        autonomousSystemCreated() {
          return this.pubSub.asyncIterator('autonomousSystemCreated');
        }
      
        @Subscription(() => AutonomousSystem, {
          name: 'autonomousSystemUpdated',
          resolve: (payload) => payload,
        })
        autonomousSystemUpdated() {
          return this.pubSub.asyncIterator('autonomousSystemUpdated');
        }
      
        @Subscription(() => String, { name: 'autonomousSystemDeleted' })
        async autonomousSystemDeleted() {
          return this.pubSub.asyncIterator('autonomousSystemDeleted');
        }

  @Mutation(() => AutonomousSystem)
  async createAutonomousSystem(
    @Args('input') createAutonomousSystemInput: CreateAutonomousSystemInput,
  ): Promise<AutonomousSystem> {
    return this.autonomousSystemService.create(createAutonomousSystemInput);
  }

  @Query(() => AutonomousSystemSearchResult)
  async searchAutonomousSystems(
    @Args('filters', { type: () => SearchAutonomousSystemInput, nullable: true }) filters: SearchAutonomousSystemInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<AutonomousSystemSearchResult> {
    return this.autonomousSystemService.searchWithFilters(filters, from, size);
  }

  @Query(() => AutonomousSystem, { nullable: true })
  async autonomousSystemById(@Args('id') id: string): Promise<AutonomousSystem> {
    return this.autonomousSystemService.findOneById(id);
  }

  @Query(() => AutonomousSystem, { nullable: true })
  async autonomousSystemByNumber(@Args('number', { type: () => Int }) number: number): Promise<AutonomousSystem> {
    return this.autonomousSystemService.findByNumber(number);
  }

  @Mutation(() => AutonomousSystem)
  async updateAutonomousSystem(
    @Args('id') id: string,
    @Args('input') updateAutonomousSystemInput: UpdateAutonomousSystemInput,
  ): Promise<AutonomousSystem> {
    return this.autonomousSystemService.update(id, updateAutonomousSystemInput);
  }

  @Mutation(() => Boolean)
  async deleteAutonomousSystem(@Args('id') id: string): Promise<boolean> {
    return this.autonomousSystemService.remove(id);
  }
}