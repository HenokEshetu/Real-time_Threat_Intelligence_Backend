import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { IPv6AddressService } from './ipv6-address.service';
import { IPv6Address } from './ipv6-address.entity';
import { CreateIPv6AddressInput, UpdateIPv6AddressInput } from './ipv6-address.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchIPv6AddressInput extends PartialType(CreateIPv6AddressInput) {}


@Resolver(() => IPv6Address)
export class IPv6AddressResolver {
  constructor(private readonly ipv6AddressService: IPv6AddressService) {}

  @Mutation(() => IPv6Address)
  async createIPv6Address(
    @Args('createIPv6AddressInput') createIPv6AddressInput: CreateIPv6AddressInput,
  ): Promise<IPv6Address> {
    return this.ipv6AddressService.create(createIPv6AddressInput);
  }

  @Query(() => [IPv6Address])
        async searchIPv6Address(
          @Args('filters', { type: () => SearchIPv6AddressInput, nullable: true }) filters: Partial<SearchIPv6AddressInput> = {}, // Accept dynamic filters
          @Args('page', { type: () => Number, defaultValue: 1 }) page: number = 1, // Pagination
          @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number = 10 // Pagination size
        ): Promise<File[]> {
          return this.ipv6AddressService.searchWithFilters(filters, page, pageSize); // Pass filters, page, and pageSize
      
      }
  @Query(() => IPv6Address)
  async ipv6Address(@Args('id') id: string): Promise<IPv6Address> {
    return this.ipv6AddressService.findOne(id);
  }

  @Mutation(() => IPv6Address)
  async updateIPv6Address(
    @Args('id') id: string,
    @Args('updateIPv6AddressInput') updateIPv6AddressInput: UpdateIPv6AddressInput,
  ): Promise<IPv6Address> {
    return this.ipv6AddressService.update(id, updateIPv6AddressInput);
  }

  @Mutation(() => Boolean)
  async removeIPv6Address(@Args('id') id: string): Promise<boolean> {
    return this.ipv6AddressService.remove(id);
  }
}