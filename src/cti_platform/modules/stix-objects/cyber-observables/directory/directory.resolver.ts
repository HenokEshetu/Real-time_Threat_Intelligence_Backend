import { Resolver,InputType, Query, Mutation, Args, ObjectType, Int, Field, Subscription } from '@nestjs/graphql';
import { DirectoryService } from './directory.service';
import { Directory } from './directory.entity';
import { CreateDirectoryInput, UpdateDirectoryInput } from './directory.input';

import { PartialType } from '@nestjs/graphql';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
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
export class DirectoryResolver  {
  constructor(
            private readonly directoryService: DirectoryService,
            @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
          ) {}
        
          // Date conversion helper
          public convertDates(payload: any): Directory {
            const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
            dateFields.forEach(field => {
              if (payload[field]) payload[field] = new Date(payload[field]);
            });
            return payload;
          }
        
          // Subscription Definitions
          @Subscription(() => Directory, {
            name: 'directoryCreated',
            resolve: (payload) => payload,
          })
          directoryCreated() {
            return this.pubSub.asyncIterator('directoryCreated');
          }
        
          @Subscription(() => Directory, {
            name: 'directoryUpdated',
            resolve: (payload) => payload,
          })
          directoryUpdated() {
            return this.pubSub.asyncIterator('directoryUpdated');
          }
        
          @Subscription(() => String, { name: 'directoryDeleted' })
          directoryDeleted() {
            return this.pubSub.asyncIterator('directoryDeleted');
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