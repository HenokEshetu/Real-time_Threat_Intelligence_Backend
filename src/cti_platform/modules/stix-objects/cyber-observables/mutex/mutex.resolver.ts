import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
  ObjectType,
  Field,
  PartialType,
} from '@nestjs/graphql';
import { MutexService } from './mutex.service';
import { Mutex } from './mutex.entity';
import { CreateMutexInput, UpdateMutexInput } from './mutex.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

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
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => Mutex)
  async createMutex(
    @Args('input') createMutexInput: CreateMutexInput,
  ): Promise<Mutex> {
    return this.mutexService.create(createMutexInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => MutexSearchResult)
  async searchMutexes(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchMutexInput, nullable: true })
    filters: SearchMutexInput = {},
  ): Promise<MutexSearchResult> {
    return this.mutexService.searchWithFilters(from, size, filters);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => Mutex, { nullable: true })
  async mutex(@Args('id') id: string): Promise<Mutex> {
    return this.mutexService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [Mutex])
  async mutexesByName(@Args('name') name: string): Promise<Mutex[]> {
    return this.mutexService.findByName(name);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => Mutex)
  async updateMutex(
    @Args('id') id: string,
    @Args('input') updateMutexInput: UpdateMutexInput,
  ): Promise<Mutex> {
    return this.mutexService.update(id, updateMutexInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteMutex(@Args('id') id: string): Promise<boolean> {
    return this.mutexService.remove(id);
  }
}
