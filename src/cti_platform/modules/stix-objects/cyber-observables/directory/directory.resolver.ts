import { Resolver,InputType, Query, Mutation, Args, ObjectType, Int, Field } from '@nestjs/graphql';
import { DirectoryService } from './directory.service';
import { Directory } from './directory.entity';
import { CreateDirectoryInput, UpdateDirectoryInput } from './directory.input';

import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
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
    super()
  }

  @Mutation(() => Directory)
  async createDirectory(
    @Args('input') createDirectoryInput: CreateDirectoryInput,
  ): Promise<Directory> {
    return this.directoryService.create(createDirectoryInput);
  }

  @Query(() => DirectorySearchResult)
  async searchDirectories(
    @Args('filters', { type: () => SearchDirectoryInput, nullable: true }) filters: SearchDirectoryInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<DirectorySearchResult> {
    return this.directoryService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Directory, { nullable: true })
  async directory(@Args('id') id: string): Promise<Directory> {
    return this.directoryService.findOne(id);
  }

  @Query(() => [Directory])
  async directoriesByPath(@Args('path') path: string): Promise<Directory[]> {
    return this.directoryService.findByPath(path);
  }

  @Mutation(() => Directory)
  async updateDirectory(
    @Args('id') id: string,
    @Args('input') updateDirectoryInput: UpdateDirectoryInput,
  ): Promise<Directory> {
    return this.directoryService.update(id, updateDirectoryInput);
  }

  @Mutation(() => Boolean)
  async deleteDirectory(@Args('id') id: string): Promise<boolean> {
    return this.directoryService.remove(id);
  }
}