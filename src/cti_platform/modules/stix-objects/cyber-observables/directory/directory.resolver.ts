import {
  Resolver,
  InputType,
  Query,
  Mutation,
  Args,
  ObjectType,
  Int,
  Field,
} from '@nestjs/graphql';
import { DirectoryService } from './directory.service';
import { Directory } from './directory.entity';
import { CreateDirectoryInput, UpdateDirectoryInput } from './directory.input';

import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchDirectoryInput extends PartialType(CreateDirectoryInput) {}

@ObjectType()
export class DirectorySearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [Directory])
  results: Directory[];
}

@Resolver(() => Directory)
export class DirectoryResolver extends BaseStixResolver(Directory) {
  public typeName = 'directory';
  constructor(private readonly directoryService: DirectoryService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => Directory)
  async createDirectory(
    @Args('input') createDirectoryInput: CreateDirectoryInput,
  ): Promise<Directory> {
    return this.directoryService.create(createDirectoryInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => DirectorySearchResult)
  async searchDirectories(
    @Args('filters', { type: () => SearchDirectoryInput, nullable: true })
    filters: SearchDirectoryInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<DirectorySearchResult> {
    return this.directoryService.searchWithFilters(filters, page, pageSize);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => Directory, { nullable: true })
  async directory(@Args('id') id: string): Promise<Directory> {
    return this.directoryService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [Directory])
  async directoriesByPath(@Args('path') path: string): Promise<Directory[]> {
    return this.directoryService.findByPath(path);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => Directory)
  async updateDirectory(
    @Args('id') id: string,
    @Args('input') updateDirectoryInput: UpdateDirectoryInput,
  ): Promise<Directory> {
    return this.directoryService.update(id, updateDirectoryInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteDirectory(@Args('id') id: string): Promise<boolean> {
    return this.directoryService.remove(id);
  }
}
