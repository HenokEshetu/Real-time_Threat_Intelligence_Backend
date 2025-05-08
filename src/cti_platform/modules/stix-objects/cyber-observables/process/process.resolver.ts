import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { ProcessService } from './process.service';
import { Process } from './process.entity';
import { CreateProcessInput, UpdateProcessInput } from './process.input';

import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
@InputType()
export class SearchProcessInput extends PartialType(CreateProcessInput) {}



@ObjectType()
export class ProcessSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Process])
  results: Process[];
}

@Resolver(() => Process)
export class ProcessResolver extends BaseStixResolver(Process) {
  public typeName = ' process';
  constructor(private readonly processService: ProcessService) {
    super()
  }

  @Mutation(() => Process)
  async createProcess(
    @Args('input') createProcessInput: CreateProcessInput,
  ): Promise<Process> {
    return this.processService.create(createProcessInput);
  }

  @Query(() => ProcessSearchResult)
  async searchProcesses(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchProcessInput, nullable: true }) filters: SearchProcessInput = {},
  ): Promise<ProcessSearchResult> {
    return this.processService.searchWithFilters(from, size, filters);
  }

  @Query(() => Process, { nullable: true })
  async process(@Args('id') id: string): Promise<Process> {
    return this.processService.findOne(id);
  }

  @Mutation(() => Process)
  async updateProcess(
    @Args('id') id: string,
    @Args('input') updateProcessInput: UpdateProcessInput,
  ): Promise<Process> {
    return this.processService.update(id, updateProcessInput);
  }

  @Mutation(() => Boolean)
  async deleteProcess(@Args('id') id: string): Promise<boolean> {
    return this.processService.remove(id);
  }
}