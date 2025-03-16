import { Resolver,InputType, Query, Mutation, Int, Args } from '@nestjs/graphql';
import { AutonomousSystemService } from './autonomous-system.service';

import { AutonomousSystem } from './autonomous-system.entity';
import { CreateAutonomousSystemInput, UpdateAutonomousSystemInput } from './autonomous-system.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchAutonomousSystemInput extends PartialType(CreateAutonomousSystemInput) {}

@Resolver(() => AutonomousSystem)
export class AutonomousSystemResolver {
  constructor(private readonly autonomousSystemService: AutonomousSystemService) {}

  @Query(() => [AutonomousSystem])
  async autonomousSystems(
    @Args('searchParams', { type: () => SearchAutonomousSystemInput, nullable: true }) searchParams?: Partial<CreateAutonomousSystemInput>,
    @Args('page', { type: () => Int, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize?: number
  ): Promise<AutonomousSystem[]> {
    const from = (page - 1) * pageSize;
    const result = await this.autonomousSystemService.searchWithFilters(searchParams || {}, from, pageSize);
    return result.results; // Return only the list of Autonomous Systems
  }

  @Query(() => AutonomousSystem)
  async autonomousSystem(@Args('id') id: string): Promise<AutonomousSystem> {
    return this.autonomousSystemService.findOne(id);
  }

  @Query(() => AutonomousSystem)
  async autonomousSystemByNumber(@Args('number') number: number): Promise<AutonomousSystem> {
    return this.autonomousSystemService.findByNumber(number);
  }

  @Mutation(() => AutonomousSystem)
  async createAutonomousSystem(
    @Args('createAutonomousSystemInput') createAutonomousSystemInput: CreateAutonomousSystemInput,
  ): Promise<AutonomousSystem> {
    return this.autonomousSystemService.create(createAutonomousSystemInput);
  }

  @Mutation(() => AutonomousSystem)
  async updateAutonomousSystem(
    @Args('id') id: string,
    @Args('updateAutonomousSystemInput') updateAutonomousSystemInput: UpdateAutonomousSystemInput,
  ): Promise<AutonomousSystem> {
    return this.autonomousSystemService.update(id, updateAutonomousSystemInput);
  }

  @Mutation(() => Boolean)
  async removeAutonomousSystem(@Args('id') id: string): Promise<boolean> {
    return this.autonomousSystemService.remove(id);
  }
}