import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
  PartialType,
  ObjectType,
  Field,
} from '@nestjs/graphql';
import { IPv6AddressService } from './ipv6-address.service';
import { IPv6Address } from './ipv6-address.entity';
import {
  CreateIPv6AddressInput,
  UpdateIPv6AddressInput,
} from './ipv6-address.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchIPv6AddressInput extends PartialType(
  CreateIPv6AddressInput,
) {}

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
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => IPv6Address)
  async createIPv6Address(
    @Args('input') createIPv6AddressInput: CreateIPv6AddressInput,
  ): Promise<IPv6Address> {
    return this.ipv6AddressService.create(createIPv6AddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => IPv6AddressSearchResult)
  async searchIPv6Addresses(
    @Args('filters', { type: () => SearchIPv6AddressInput, nullable: true })
    filters: SearchIPv6AddressInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IPv6AddressSearchResult> {
    return this.ipv6AddressService.searchWithFilters(filters, page, pageSize);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => IPv6Address, { nullable: true })
  async ipv6Address(@Args('id') id: string): Promise<IPv6Address> {
    return this.ipv6AddressService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [IPv6Address])
  async ipv6AddressesByValue(
    @Args('value') value: string,
  ): Promise<IPv6Address[]> {
    return this.ipv6AddressService.findByValue(value);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => IPv6Address)
  async updateIPv6Address(
    @Args('id') id: string,
    @Args('input') updateIPv6AddressInput: UpdateIPv6AddressInput,
  ): Promise<IPv6Address> {
    return this.ipv6AddressService.update(id, updateIPv6AddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteIPv6Address(@Args('id') id: string): Promise<boolean> {
    return this.ipv6AddressService.remove(id);
  }
}
