import { Resolver,InputType, Query, Mutation, Args,Int, Subscription } from '@nestjs/graphql';
import { UrlService } from './url.service';
import { Url } from './url.entity';
import { CreateUrlInput, UpdateUrlInput } from './url.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
@InputType()
export class SearchUrlInput extends PartialType(CreateUrlInput) {}




@ObjectType()
export class UrlSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Url])
  results: Url[];
}

@Resolver(() => Url)
export class UrlResolver  {
 
  constructor(
        private readonly urlService: UrlService,
        @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
      ) { }
    
      // Date conversion helper
      public convertDates(payload: any): Url {
        const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
        dateFields.forEach(field => {
          if (payload[field]) payload[field] = new Date(payload[field]);
        });
        return payload;
      }
    
      // Subscription Definitions
      @Subscription(() => Url, {
        name: 'urlCreated',
        resolve: (payload) => payload,
      })
      urlCreated() {
        return this.pubSub.asyncIterator('urlCreated');
      }
    
      @Subscription(() => Url, {
        name: 'urlUpdated',
        resolve: (payload) => payload,
      })
      urlUpdated() {
        return this.pubSub.asyncIterator('urlUpdated');
      }
    
      @Subscription(() => String, { name: 'urlDeleted' })
      urlDeleted() {
        return this.pubSub.asyncIterator('urlDeleted');
      }
  

  @Mutation(() => Url)
  async createUrl(
    @Args('input') createUrlInput: CreateUrlInput,
  ): Promise<Url> {
    return this.urlService.create(createUrlInput);
  }

  @Query(() => UrlSearchResult)
  async searchUrls(
    @Args('filters', { type: () => SearchUrlInput, nullable: true }) filters: SearchUrlInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<UrlSearchResult> {
    return this.urlService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Url, { nullable: true })
  async url(@Args('id') id: string): Promise<Url> {
    return this.urlService.findOne(id);
  }

  @Mutation(() => Url)
  async updateUrl(
    @Args('id') id: string,
    @Args('input') updateUrlInput: UpdateUrlInput,
  ): Promise<Url> {
    return this.urlService.update(id, updateUrlInput);
  }

  @Mutation(() => Boolean)
  async deleteUrl(@Args('id') id: string): Promise<boolean> {
    return this.urlService.remove(id);
  }
}