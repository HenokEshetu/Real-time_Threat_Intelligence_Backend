import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { MutexService } from './mutex.service';
import { Mutex } from './mutex.entity';
import { CreateMutexInput, UpdateMutexInput } from './mutex.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
@InputType()
export class SearchMutexInput extends PartialType(CreateMutexInput) {}



@ObjectType()
export class MutexSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Mutex])
  results: Mutex[];
}

@Resolver(() => Mutex)
export class MutexResolver extends BaseStixResolver(Mutex) {
  public typeName = ' mutex';
  constructor(private readonly mutexService: MutexService) {
    super()
  }

  @Mutation(() => Mutex)
  async createMutex(
    @Args('input') createMutexInput: CreateMutexInput,
  ): Promise<Mutex> {
    return this.mutexService.create(createMutexInput);
  }

  @Query(() => MutexSearchResult)
  async searchMutexes(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchMutexInput, nullable: true }) filters: SearchMutexInput = {},
  ): Promise<MutexSearchResult> {
    return this.mutexService.searchWithFilters(from, size, filters);
  }

  @Query(() => Mutex, { nullable: true })
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
    @Args('input') updateMutexInput: UpdateMutexInput,
  ): Promise<Mutex> {
    return this.mutexService.update(id, updateMutexInput);
  }

  @Mutation(() => Boolean)
  async deleteMutex(@Args('id') id: string): Promise<boolean> {
    return this.mutexService.remove(id);
  }
}