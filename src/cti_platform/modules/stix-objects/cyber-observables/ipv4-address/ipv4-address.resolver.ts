import { Resolver,InputType, Query, Mutation, Args } from '@nestjs/graphql';
import { IPv4AddressService } from './ipv4-address.service';
import { IPv4Address } from './ipv4-address.entity';
import { CreateIPv4AddressInput, UpdateIPv4AddressInput } from './ipv4-address.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchIPv4AddressInput extends PartialType(CreateIPv4AddressInput) {}


@Resolver(() => IPv4Address)
export class IPv4AddressResolver {
  constructor(private readonly ipv4AddressService: IPv4AddressService) {}

  @Query(() => [IPv4Address])
      async searchAddress(
        @Args('filters', { type: () => SearchIPv4AddressInput, nullable: true }) filters: Partial<SearchIPv4AddressInput> = {}, // Accept dynamic filters
        @Args('page', { type: () => Number, defaultValue: 1 }) page: number = 1, // Pagination
        @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number = 10 // Pagination size
      ): Promise<File[]> {
        return this.ipv4AddressService.searchWithFilters(filters, page, pageSize); // Pass filters, page, and pageSize
    
    }
  @Query(() => IPv4Address)
  async ipv4Address(@Args('id') id: string): Promise<IPv4Address> {
    return this.ipv4AddressService.findOne(id);
  }

  @Mutation(() => IPv4Address)
  async createIPv4Address(
    @Args('createIPv4AddressInput') createIPv4AddressInput: CreateIPv4AddressInput,
  ): Promise<IPv4Address> {
    return this.ipv4AddressService.create(createIPv4AddressInput);
  }

  @Mutation(() => IPv4Address)
  async updateIPv4Address(
    @Args('id') id: string,
    @Args('updateIPv4AddressInput') updateIPv4AddressInput: UpdateIPv4AddressInput,
  ): Promise<IPv4Address> {
    return this.ipv4AddressService.update(id, updateIPv4AddressInput);
  }

  @Mutation(() => Boolean)
  async removeIPv4Address(@Args('id') id: string): Promise<boolean> {
    await this.ipv4AddressService.remove(id);
    return true;
  }
}