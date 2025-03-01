import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { MACAddressService } from './mac-address.service';
import { MACAddress } from './mac-address.entity';
import { CreateMACAddressInput, UpdateMACAddressInput } from './mac-address.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchMACAddressInput extends PartialType(CreateMACAddressInput) {}

@Resolver(() => MACAddress)
export class MACAddressResolver {
  constructor(private readonly macAddressService: MACAddressService) {}

  @Mutation(() => MACAddress)
  async createMACAddress(
    @Args('createMACAddressInput') createMACAddressInput: CreateMACAddressInput,
  ): Promise<MACAddress> {
    return this.macAddressService.create(createMACAddressInput);
  }

  
// Search MAC addresses dynamically using filters
@Query(() => [MACAddress], { name: 'mac_addresses' })
async searchMACAddresses(
  @Args('from', { type: () => Number, nullable: true }) from?: number,
  @Args('size', { type: () => Number, nullable: true }) size?: number,
  @Args('filter', { type: () => SearchMACAddressInput, nullable: true }) filter?: Partial<SearchMACAddressInput>,
): Promise<MACAddress[]> {
  return this.macAddressService.searchWithFilters(from ?? 0, size ?? 10, filter ?? {});
}


  @Query(() => MACAddress)
  async macAddress(@Args('id') id: string): Promise<MACAddress> {
    return this.macAddressService.findOne(id);
  }

  @Mutation(() => MACAddress)
  async updateMACAddress(
    @Args('id') id: string,
    @Args('updateMACAddressInput') updateMACAddressInput: UpdateMACAddressInput,
  ): Promise<MACAddress> {
    return this.macAddressService.update(id, updateMACAddressInput);
  }

  @Mutation(() => Boolean)
  async removeMACAddress(@Args('id') id: string): Promise<boolean> {
    return this.macAddressService.remove(id);
  }
}