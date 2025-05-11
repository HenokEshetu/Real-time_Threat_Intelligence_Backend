import { Resolver,InputType, Query, Mutation, Args,Int, Subscription } from '@nestjs/graphql';
import { IPv4AddressService } from './ipv4-address.service';
import { IPv4Address } from './ipv4-address.entity';
import { CreateIPv4AddressInput, UpdateIPv4AddressInput } from './ipv4-address.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchIPv4AddressInput extends PartialType(CreateIPv4AddressInput) {}

import { ObjectType, Field } from '@nestjs/graphql';
import { Inject } from '@nestjs/common';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';


@ObjectType()
export class IPv4AddressSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [IPv4Address])
  results: IPv4Address[];
}

@Resolver(() => IPv4Address)
export class IPv4AddressResolver   {
 
  constructor(
        private readonly ipv4AddressService: IPv4AddressService,
        @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
      ) { }
    
      // Date conversion helper
      public convertDates(payload: any): IPv4Address {
        const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
        dateFields.forEach(field => {
          if (payload[field]) payload[field] = new Date(payload[field]);
        });
        return payload;
      }
    
      // Subscription Definitions
      @Subscription(() => IPv4Address, {
        name: 'ipv4AddressCreated',
        resolve: (payload) => payload,
      })
      ipv4AddrCreated() {
        return this.pubSub.asyncIterator('ipv4AddressCreated');
      }
    
      @Subscription(() => IPv4Address, {
        name: 'ipv4AddressUpdated',
        resolve: (payload) => payload,
      })
      ipv4AddrUpdated() {
        return this.pubSub.asyncIterator('ipv4AddressUpdated');
      }
    
      @Subscription(() => String, { name: 'ipv4AddressDeleted' })
      ipv4AddrDeleted() {
        return this.pubSub.asyncIterator('ipv4AddressDeleted');
      }

  @Mutation(() => IPv4Address)
  async createIPv4Address(
    @Args('input') createIPv4AddressInput: CreateIPv4AddressInput,
  ): Promise<IPv4Address> {
    return this.ipv4AddressService.create(createIPv4AddressInput);
  }

  @Query(() => IPv4AddressSearchResult)
  async searchIPv4Addresses(
    @Args('filters', { type: () => SearchIPv4AddressInput, nullable: true }) filters: SearchIPv4AddressInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IPv4AddressSearchResult> {
    return this.ipv4AddressService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => IPv4Address, { nullable: true })
  async ipv4Address(@Args('id') id: string): Promise<IPv4Address> {
    return this.ipv4AddressService.findOne(id);
  }

  @Query(() => [IPv4Address])
  async ipv4AddressesByValue(@Args('value') value: string): Promise<IPv4Address[]> {
    return this.ipv4AddressService.findByValue(value);
  }

  @Mutation(() => IPv4Address)
  async updateIPv4Address(
    @Args('id') id: string,
    @Args('input') updateIPv4AddressInput: UpdateIPv4AddressInput,
  ): Promise<IPv4Address> {
    return this.ipv4AddressService.update(id, updateIPv4AddressInput);
  }

  @Mutation(() => Boolean)
  async deleteIPv4Address(@Args('id') id: string): Promise<boolean> {
    return this.ipv4AddressService.remove(id);
  }
}