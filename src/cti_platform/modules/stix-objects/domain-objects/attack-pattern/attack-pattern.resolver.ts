import { Resolver,InputType, Query, Mutation, Args, Int } from '@nestjs/graphql';
import { AttackPatternService } from './attack-pattern.service';
import { AttackPattern } from './attack-pattern.entity';
import { CreateAttackPatternInput, UpdateAttackPatternInput } from './attack-pattern.input';



import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchAttackPatternInput extends PartialType(CreateAttackPatternInput){}

@Resolver(() => AttackPattern)
export class AttackPatternResolver {
  constructor(private readonly attackPatternService: AttackPatternService) {}

  //  Create Attack Pattern
  @Mutation(() => AttackPattern)
  async createAttackPattern(
    @Args('input') input: CreateAttackPatternInput,
  ): Promise<AttackPattern> {
    return this.attackPatternService.create(input);
  }

  //  Find one Attack Pattern by ID
  @Query(() => AttackPattern, { nullable: true })
  async attackPattern(@Args('id') id: string): Promise<AttackPattern> {
    return this.attackPatternService.findOne(id);
  }

  //  Update Attack Pattern
  @Mutation(() => AttackPattern)
  async updateAttackPattern(
    @Args('id') id: string,
    @Args('input') input: UpdateAttackPatternInput,
  ): Promise<AttackPattern> {
    return this.attackPatternService.update(id, input);
  }

  // Delete Attack Pattern
  @Mutation(() => Boolean)
  async removeAttackPattern(@Args('id') id: string): Promise<boolean> {
    return this.attackPatternService.remove(id);
  }

  // Search Attack Patterns with filters & pagination
  @Query(() => [AttackPattern])
  async searchAttackPatterns(
    @Args('filters', { type: () => SearchAttackPatternInput, nullable: true }) filters: Partial<SearchAttackPatternInput>,
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<{ total: number; results: AttackPattern[] }> {
    return this.attackPatternService.searchWithFilters(filters, page, pageSize);
  }
}
