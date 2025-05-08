import { Resolver,InputType, Query, Mutation, Args, Int } from '@nestjs/graphql';
import { AttackPatternService } from './attack-pattern.service';
import { AttackPattern } from './attack-pattern.entity';
import { CreateAttackPatternInput, UpdateAttackPatternInput } from './attack-pattern.input';
import { ObjectType, Field } from '@nestjs/graphql';


import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

@InputType()
export class SearchAttackPatternInput extends PartialType(CreateAttackPatternInput){}


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
export class AttackPatternResolver extends BaseStixResolver(AttackPattern){
  public typeName = 'attack-pattern';
  constructor(private readonly attackPatternService: AttackPatternService) {
    super();
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