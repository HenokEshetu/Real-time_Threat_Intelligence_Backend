import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { ProcessService } from './process.service';
import { Process } from './process.entity';
import { CreateProcessInput, UpdateProcessInput } from './process.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchProcessInput extends PartialType(CreateProcessInput) {}


@Resolver(() => Process)
export class ProcessResolver {
  constructor(private readonly processService: ProcessService) {}

  @Mutation(() => Process)
  async createProcess(
    @Args('createProcessInput') createProcessInput: CreateProcessInput,
  ): Promise<Process> {
    return this.processService.create(createProcessInput);
  }

  // Search process dynamically using filters
  @Query(() => [Process], { name: 'process' })
  async searchProcess(
    @Args('from', { type: () => Number, nullable: true }) from?: number,
    @Args('size', { type: () => Number, nullable: true }) size?: number,
    @Args('filter', { type: () => SearchProcessInput, nullable: true }) filter?: SearchProcessInput,
  ): Promise<Process[]> {
    return this.processService.searchWithFilters(from ?? 0, size ?? 10, filter ?? {});
  }
  

  @Query(() => Process)
  async process(@Args('id') id: string): Promise<Process> {
    return this.processService.findOne(id);
  }

  @Mutation(() => Process)
  async updateProcess(
    @Args('id') id: string,
    @Args('updateProcessInput') updateProcessInput: UpdateProcessInput,
  ): Promise<Process> {
    return this.processService.update(id, updateProcessInput);
  }

  @Mutation(() => Boolean)
  async removeProcess(@Args('id') id: string): Promise<boolean> {
    return this.processService.remove(id);
  }
}