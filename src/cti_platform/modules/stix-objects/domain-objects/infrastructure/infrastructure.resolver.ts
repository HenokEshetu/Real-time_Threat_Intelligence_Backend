import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { InfrastructureService } from './infrastructure.service';
import { Infrastructure } from './infrastructure.entity';
import { CreateInfrastructureInput, UpdateInfrastructureInput } from './infrastructure.input';



import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchInfrastructureInput extends PartialType(CreateInfrastructureInput){}



@Resolver(() => Infrastructure)
export class InfrastructureResolver {
  constructor(private readonly infrastructureService: InfrastructureService) {}

  // Create Infrastructure
  @Mutation(() => Infrastructure)
  async createInfrastructure(
    @Args('createInfrastructureInput') createInfrastructureInput: CreateInfrastructureInput
  ): Promise<Infrastructure> {
    return this.infrastructureService.create(createInfrastructureInput);
  }

  // Find Infrastructure by ID
  @Query(() => Infrastructure, { nullable: true })
  async getInfrastructure(@Args('id') id: string): Promise<Infrastructure> {
    return this.infrastructureService.findOne(id);
  }

  // Update Infrastructure
  @Mutation(() => Infrastructure)
  async updateInfrastructure(
    @Args('id') id: string,
    @Args('updateInfrastructureInput') updateInfrastructureInput: UpdateInfrastructureInput
  ): Promise<Infrastructure> {
    return this.infrastructureService.update(id, updateInfrastructureInput);
  }

  // Delete Infrastructure
  @Mutation(() => Boolean)
  async removeInfrastructure(@Args('id') id: string): Promise<boolean> {
    return this.infrastructureService.remove(id);
  }

  // Search Infrastructure with Filters
  @Query(() => [Infrastructure])
  async searchInfrastructureWithFilters(
    @Args('filters', { type: () => CreateInfrastructureInput, nullable: true }) filters?: Partial<CreateInfrastructureInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number
  ): Promise<{ total: number; page: number; pageSize: number; results: Infrastructure[] }> {
    return this.infrastructureService.searchInfrastructureWithFilters(filters, page, pageSize);
  }
}
