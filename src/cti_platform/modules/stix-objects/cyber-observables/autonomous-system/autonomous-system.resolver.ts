import { Resolver,InputType, Query, Mutation, Int,ObjectType, Field, Args, } from '@nestjs/graphql';
import { AutonomousSystemService } from './autonomous-system.service';
import { AutonomousSystem } from './autonomous-system.entity';
import { CreateAutonomousSystemInput, UpdateAutonomousSystemInput } from './autonomous-system.input';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
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
export class AutonomousSystemResolver extends BaseStixResolver(AutonomousSystem) {
  public typeName = 'autonomous-system';
  constructor(private readonly autonomousSystemService: AutonomousSystemService) {
    super()
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