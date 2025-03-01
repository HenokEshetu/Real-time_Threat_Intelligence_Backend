import { Resolver,InputType, Query, Mutation, Args } from '@nestjs/graphql';
import { DirectoryService } from './directory.service';
import{InternalServerErrorException} from '@nestjs/common'
import { Directory } from './directory.entity';
import { CreateDirectoryInput, UpdateDirectoryInput } from './directory.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchDirectoryInput extends PartialType(CreateDirectoryInput) {}


@Resolver(() => Directory)
export class DirectoryResolver {
  constructor(private readonly directoryService: DirectoryService) {}

  // The query method to get directories based on search filters
  @Query(() => [Directory])
  async directories(
    @Args('filters', { type: () => SearchDirectoryInput, nullable: true }) filters: Partial<SearchDirectoryInput>, // Filters for the search
    @Args('page', { type: () => Number, nullable: true, defaultValue: 1 }) page: number, // Pagination: Page number (default: 1)
    @Args('pageSize', { type: () => Number, nullable: true, defaultValue: 10 }) pageSize: number // Pagination: Page size (default: 10)
  ): Promise<Directory[]> {
    try {
      const result = await this.directoryService.searchWithFilters(filters, page, pageSize); // Call the service method
      return result.results; // Return the search results
    } catch (error) {
      throw new InternalServerErrorException('Error fetching directories');
    }
  }

  @Query(() => Directory)
  async directory(@Args('id') id: string): Promise<Directory> {
    return this.directoryService.findOne(id);
  }

  @Query(() => [Directory])
  async directoriesByPath(@Args('path') path: string): Promise<Directory[]> {
    return this.directoryService.findByPath(path);
  }

  @Mutation(() => Directory)
  async createDirectory(
    @Args('createDirectoryInput') createDirectoryInput: CreateDirectoryInput,
  ): Promise<Directory> {
    return this.directoryService.create(createDirectoryInput);
  }

  @Mutation(() => Directory)
  async updateDirectory(
    @Args('id') id: string,
    @Args('updateDirectoryInput') updateDirectoryInput: UpdateDirectoryInput,
  ): Promise<Directory> {
    return this.directoryService.update(id, updateDirectoryInput);
  }

  @Mutation(() => Boolean)
  async removeDirectory(@Args('id') id: string): Promise<boolean> {
    return this.directoryService.remove(id);
  }
}