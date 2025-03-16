import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { InfrastructureService } from './infrastructure.service';
import { Infrastructure } from './infrastructure.entity';
import { CreateInfrastructureInput, UpdateInfrastructureInput } from './infrastructure.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchInfrastructureInput extends PartialType(CreateInfrastructureInput){}


@ObjectType()
export class InfrastructureSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Infrastructure])
  results: Infrastructure[];
}

@Resolver(() => Infrastructure)
export class InfrastructureResolver {
  constructor(private readonly infrastructureService: InfrastructureService) {}

  @Mutation(() => Infrastructure)
  async createInfrastructure(
    @Args('input') createInfrastructureInput: CreateInfrastructureInput,
  ): Promise<Infrastructure> {
    return this.infrastructureService.create(createInfrastructureInput);
  }

  @Query(() => InfrastructureSearchResult)
  async searchInfrastructures(
    @Args('filters', { type: () => SearchInfrastructureInput, nullable: true }) filters: SearchInfrastructureInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<InfrastructureSearchResult> {
    return this.infrastructureService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Infrastructure, { nullable: true })
  async infrastructure(@Args('id') id: string): Promise<Infrastructure> {
    return this.infrastructureService.findOne(id);
  }

  @Mutation(() => Infrastructure)
  async updateInfrastructure(
    @Args('id') id: string,
    @Args('input') updateInfrastructureInput: UpdateInfrastructureInput,
  ): Promise<Infrastructure> {
    return this.infrastructureService.update(id, updateInfrastructureInput);
  }

  @Mutation(() => Boolean)
  async deleteInfrastructure(@Args('id') id: string): Promise<boolean> {
    return this.infrastructureService.remove(id);
  }
}