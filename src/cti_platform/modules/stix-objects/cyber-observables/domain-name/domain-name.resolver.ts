import { Resolver, Query, Mutation,InputType, Args, Int, Subscription } from '@nestjs/graphql';
import { DomainNameService } from './domain-name.service';
import { DomainName } from './domain-name.entity';
import { CreateDomainNameInput, UpdateDomainNameInput } from './domain-name.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchDomainNameInput extends PartialType(CreateDomainNameInput) {}

import { ObjectType, Field } from '@nestjs/graphql';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';


@ObjectType()
export class DomainNameSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [DomainName])
  results: DomainName[];
}

@Resolver(() => DomainName)
export class DomainNameResolver  {
 
   constructor(
              private readonly domainNameService: DomainNameService,
              @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
            ) {}
          
            // Date conversion helper
            public convertDates(payload: any): DomainName {
              const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
              dateFields.forEach(field => {
                if (payload[field]) payload[field] = new Date(payload[field]);
              });
              return payload;
            }
          
            // Subscription Definitions
            @Subscription(() => DomainName, {
              name: 'domainNameCreated',
              resolve: (payload) => payload,
            })
            directoryCreated() {
              return this.pubSub.asyncIterator('domainNameCreated');
            }
          
            @Subscription(() => DomainName, {
              name: 'domainNameUpdated',
              resolve: (payload) => payload,
            })
            directoryUpdated() {
              return this.pubSub.asyncIterator('domainNameUpdated');
            }
          
            @Subscription(() => String, { name: 'domainNameDeleted' })
            directoryDeleted() {
              return this.pubSub.asyncIterator('domainNameDeleted');
            }

  @Mutation(() => DomainName)
  async createDomainName(
    @Args('input') createDomainNameInput: CreateDomainNameInput,
  ): Promise<DomainName> {
    return this.domainNameService.create(createDomainNameInput);
  }

  @Query(() => DomainNameSearchResult)
  async searchDomainNames(
    @Args('filters', { type: () => SearchDomainNameInput, nullable: true }) filters: SearchDomainNameInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<DomainNameSearchResult> {
    return this.domainNameService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => DomainName, { nullable: true })
  async domainName(@Args('id') id: string): Promise<DomainName> {
    return this.domainNameService.findOne(id);
  }

  @Query(() => [DomainName])
  async domainNamesByValue(@Args('value') value: string): Promise<DomainName[]> {
    return this.domainNameService.findByValue(value);
  }

  @Mutation(() => DomainName)
  async updateDomainName(
    @Args('id') id: string,
    @Args('input') updateDomainNameInput: UpdateDomainNameInput,
  ): Promise<DomainName> {
    return this.domainNameService.update(id, updateDomainNameInput);
  }

  @Mutation(() => Boolean)
  async deleteDomainName(@Args('id') id: string): Promise<boolean> {
    return this.domainNameService.remove(id);
  }
}