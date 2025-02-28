import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { MutexService } from './mutex.service';
import { Mutex } from './mutex.entity';
import { CreateMutexInput, UpdateMutexInput } from './mutex.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchMutexInput extends PartialType(CreateMutexInput) {}



@Resolver(() => Mutex)
export class MutexResolver {
  constructor(private readonly mutexService: MutexService) {}

  @Mutation(() => Mutex)
  async createMutex(
    @Args('createMutexInput') createMutexInput: CreateMutexInput,
  ): Promise<Mutex> {
    return this.mutexService.create(createMutexInput);
  }

  

  @Query(() => Mutex)
  async mutex(@Args('id') id: string): Promise<Mutex> {
    return this.mutexService.findOne(id);
  }

  @Query(() => [Mutex])
  async mutexesByName(@Args('name') name: string): Promise<Mutex[]> {
    return this.mutexService.findByName(name);
  }

  @Mutation(() => Mutex)
  async updateMutex(
    @Args('id') id: string,
    @Args('updateMutexInput') updateMutexInput: UpdateMutexInput,
  ): Promise<Mutex> {
    return this.mutexService.update(id, updateMutexInput);
  }

  @Mutation(() => Boolean)
  async removeMutex(@Args('id') id: string): Promise<boolean> {
    return this.mutexService.remove(id);
  }


// Search Mutex  dynamically using filters
@Query(() => [Mutex], { name: 'mutexes' })
async searchMutex(
  @Args('from', { type: () => Number, nullable: true }) from?: number,
  @Args('size', { type: () => Number, nullable: true }) size?: number,
  @Args('filter', { type: () => SearchMutexInput, nullable: true }) filter?: SearchMutexInput,
): Promise<Mutex[]> {
  return this.mutexService.searchWithFilters(from ?? 0, size ?? 10, filter ?? {});
}




}