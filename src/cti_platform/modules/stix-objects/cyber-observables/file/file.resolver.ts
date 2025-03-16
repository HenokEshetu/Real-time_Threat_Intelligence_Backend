import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { FileService } from './file.service';
import { File } from './file.entity';
import { CreateFileInput, UpdateFileInput } from './file.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchFileInput extends PartialType(CreateFileInput) {}


@Resolver(() => File)
export class FileResolver {
  constructor(private readonly fileService: FileService) {}

  @Query(() => File)
  async file(@Args('id') id: string): Promise<File> {
    return this.fileService.findOne(id);
  }

  @Mutation(() => File)
  async createFile(
    @Args('createFileInput') createFileInput: CreateFileInput,
  ): Promise<File> {
    return this.fileService.create(createFileInput);
  }

  @Mutation(() => File)
  async updateFile(
    @Args('id') id: string,
    @Args('updateFileInput') updateFileInput: UpdateFileInput,
  ): Promise<File> {
    return this.fileService.update(id, updateFileInput);
  }

  @Mutation(() => Boolean)
  async removeFile(@Args('id') id: string): Promise<boolean> {
    await this.fileService.remove(id);
    return true;
  }


  @Query(() => [File])
    async searchFile(
      @Args('filters', { type: () => SearchFileInput, nullable: true }) filters: Partial<SearchFileInput> = {}, // Accept dynamic filters
      @Args('page', { type: () => Number, defaultValue: 1 }) page: number = 1, // Pagination
      @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number = 10 // Pagination size
    ): Promise<File[]> {
      return this.fileService.searchWithFilters(filters, page, pageSize); // Pass filters, page, and pageSize
  
  }
}
