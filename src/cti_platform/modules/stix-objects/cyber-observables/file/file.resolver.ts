import { Resolver, Query, InputType, Mutation, Args,  Int, Subscription  } from '@nestjs/graphql';
import { FileService } from './file.service';
import { File } from './file.entity';
import { CreateFileInput, UpdateFileInput } from './file.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
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
export class FileResolver  {
  constructor(
      private readonly fileService: FileService,
      @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
    ) { }
  
    // Date conversion helper
    public convertDates(payload: any): File {
      const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
      dateFields.forEach(field => {
        if (payload[field]) payload[field] = new Date(payload[field]);
      });
      return payload;
    }
  
    // Subscription Definitions
    @Subscription(() => File, {
      name: 'fileCreated',
      resolve: (payload) => payload,
    })
    fileCreated() {
      return this.pubSub.asyncIterator('fileCreated');
    }
  
    @Subscription(() => File, {
      name: 'fileUpdated',
      resolve: (payload) => payload,
    })
    fileUpdated() {
      return this.pubSub.asyncIterator('fileUpdated');
    }
  
    @Subscription(() => String, { name: 'fileDeleted' })
    fileDeleted() {
      return this.pubSub.asyncIterator('fileDeleted');
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
