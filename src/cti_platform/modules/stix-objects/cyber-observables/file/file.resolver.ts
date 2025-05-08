import { Resolver, Query, InputType, Mutation, Args,  Int  } from '@nestjs/graphql';
import { FileService } from './file.service';
import { File } from './file.entity';
import { CreateFileInput, UpdateFileInput } from './file.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
@InputType()
export class SearchFileInput extends PartialType(CreateFileInput) {

}

@ObjectType()
export class FileSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [File])
  results: File[];
}

@Resolver(() => File)
export class FileResolver extends BaseStixResolver(File) {
  public typeName = 'file';
  constructor(private readonly fileService: FileService) {
    super()
  }

  @Mutation(() => File)
  async createFile(
    @Args('input') createFileInput: CreateFileInput,
  ): Promise<File> {
    return this.fileService.create(createFileInput);
  }

  @Query(() => FileSearchResult)
  async searchFiles(
    @Args('filters', { type: () => SearchFileInput, nullable: true }) filters: SearchFileInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<FileSearchResult> {
    return this.fileService.searchWithFilters(filters, from, size);
  }

  @Query(() => File, { nullable: true })
  async file(@Args('id') id: string): Promise<File> {
    return this.fileService.findOne(id);
  }

  @Query(() => [File])
  async filesByHash(@Args('hashValue') hashValue: string): Promise<File[]> {
    return this.fileService.findByHash(hashValue);
  }

  @Mutation(() => File)
  async updateFile(
    @Args('id') id: string,
    @Args('input') updateFileInput: UpdateFileInput,
  ): Promise<File> {
    return this.fileService.update(id, updateFileInput);
  }

  @Mutation(() => Boolean)
  async deleteFile(@Args('id') id: string): Promise<boolean> {
    return this.fileService.remove(id);
  }
}
