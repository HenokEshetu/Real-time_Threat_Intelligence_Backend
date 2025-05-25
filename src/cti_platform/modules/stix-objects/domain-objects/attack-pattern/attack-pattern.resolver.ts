import { Resolver, InputType, Query, Mutation, Args, Int, Subscription, OmitType } from '@nestjs/graphql';
import { AttackPatternService } from './attack-pattern.service';
import { AttackPattern } from './attack-pattern.entity';
import { CreateAttackPatternInput, UpdateAttackPatternInput } from './attack-pattern.input';
import { ObjectType, Field } from '@nestjs/graphql';


import { PartialType } from '@nestjs/graphql';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { DateRangeInput } from '../indicator/indicator.input';


@InputType()
export class SearchAttackPatternInput extends PartialType(OmitType(CreateAttackPatternInput, ['modified', 'created'] as const)) {      

@Field(() => DateRangeInput, { nullable: true })
  created?: DateRangeInput;

  @Field(() => DateRangeInput, { nullable: true })
  modified?: DateRangeInput;
}


@ObjectType()
export class AttackPatternSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [AttackPattern])
  results: AttackPattern[];
}

@Resolver(() => AttackPattern)
export class AttackPatternResolver {
 
  constructor(
    private readonly attackPatternService: AttackPatternService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): AttackPattern {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => AttackPattern, {
    name: 'attackPatternCreated',
    resolve: (payload) => payload,
  })
  attackPatternCreated() {
    return this.pubSub.asyncIterator('attack-patternCreated');
  }

  @Subscription(() => AttackPattern, {
    name: 'attackPatternUpdated',
    resolve: (payload) => payload,
  })
  attackPatternUpdated() {
    return this.pubSub.asyncIterator('attackPatternUpdated');
  }

  @Subscription(() => String, { name: 'attackPatternDeleted' })
  attackPatternDeleted() {
    return this.pubSub.asyncIterator('attackPatternDeleted');
  }
  @Mutation(() => AttackPattern)
  async createAttackPattern(
    @Args('input') createAttackPatternInput: CreateAttackPatternInput,
  ): Promise<AttackPattern> {
    return this.attackPatternService.create(createAttackPatternInput);
  }

  @Query(() => AttackPatternSearchResult)
  async searchAttackPatterns(
    @Args('filters', { type: () => SearchAttackPatternInput, nullable: true }) filters: SearchAttackPatternInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<AttackPatternSearchResult> {
    return this.attackPatternService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => AttackPattern, { nullable: true })
  async attackPattern(@Args('id') id: string): Promise<AttackPattern> {
    return this.attackPatternService.findOne(id);
  }

  @Mutation(() => AttackPattern)
  async updateAttackPattern(
    @Args('id') id: string,
    @Args('input') updateAttackPatternInput: UpdateAttackPatternInput,
  ): Promise<AttackPattern> {
    return this.attackPatternService.update(id, updateAttackPatternInput);
  }

  @Mutation(() => Boolean)
  async deleteAttackPattern(@Args('id') id: string): Promise<boolean> {
    return this.attackPatternService.remove(id);
  }
}