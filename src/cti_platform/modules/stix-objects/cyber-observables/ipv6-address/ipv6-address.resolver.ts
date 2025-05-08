import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { IPv6AddressService } from './ipv6-address.service';
import { IPv6Address } from './ipv6-address.entity';
import { CreateIPv6AddressInput, UpdateIPv6AddressInput } from './ipv6-address.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchIPv6AddressInput extends PartialType(CreateIPv6AddressInput) {}


import { ObjectType, Field } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

@ObjectType()
export class IPv6AddressSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [IPv6Address])
  results: IPv6Address[];
}

@Resolver(() => IPv6Address)
export class IPv6AddressResolver extends BaseStixResolver(IPv6Address) {
  public typeName = ' ipv6-addr';
  constructor(private readonly ipv6AddressService: IPv6AddressService) {
    super()
  }

  @Mutation(() => IPv6Address)
  async createIPv6Address(
    @Args('input') createIPv6AddressInput: CreateIPv6AddressInput,
  ): Promise<IPv6Address> {
    return this.ipv6AddressService.create(createIPv6AddressInput);
  }

  @Query(() => IPv6AddressSearchResult)
  async searchIPv6Addresses(
    @Args('filters', { type: () => SearchIPv6AddressInput, nullable: true }) filters: SearchIPv6AddressInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IPv6AddressSearchResult> {
    return this.ipv6AddressService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => IPv6Address, { nullable: true })
  async ipv6Address(@Args('id') id: string): Promise<IPv6Address> {
    return this.ipv6AddressService.findOne(id);
  }

  @Query(() => [IPv6Address])
  async ipv6AddressesByValue(@Args('value') value: string): Promise<IPv6Address[]> {
    return this.ipv6AddressService.findByValue(value);
  }

  @Mutation(() => IPv6Address)
  async updateIPv6Address(
    @Args('id') id: string,
    @Args('input') updateIPv6AddressInput: UpdateIPv6AddressInput,
  ): Promise<IPv6Address> {
    return this.ipv6AddressService.update(id, updateIPv6AddressInput);
  }

  @Mutation(() => Boolean)
  async deleteIPv6Address(@Args('id') id: string): Promise<boolean> {
    return this.ipv6AddressService.remove(id);
  }
}