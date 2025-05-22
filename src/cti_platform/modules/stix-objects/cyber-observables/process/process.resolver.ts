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
import { ProcessService } from './process.service';
import { Process } from './process.entity';
import { CreateProcessInput, UpdateProcessInput } from './process.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

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
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => Process)
  async createProcess(
    @Args('input') createProcessInput: CreateProcessInput,
  ): Promise<Process> {
    return this.processService.create(createProcessInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => ProcessSearchResult)
  async searchProcesses(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchProcessInput, nullable: true })
    filters: SearchProcessInput = {},
  ): Promise<ProcessSearchResult> {
    return this.processService.searchWithFilters(from, size, filters);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => Process, { nullable: true })
  async process(@Args('id') id: string): Promise<Process> {
    return this.processService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => Process)
  async updateProcess(
    @Args('id') id: string,
    @Args('input') updateProcessInput: UpdateProcessInput,
  ): Promise<Process> {
    return this.processService.update(id, updateProcessInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteProcess(@Args('id') id: string): Promise<boolean> {
    return this.processService.remove(id);
  }
}
