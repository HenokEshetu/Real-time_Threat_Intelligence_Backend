import {
  Resolver,
  InputType,
  Query,
  Mutation,
  Args,
  Int,
  PartialType,
  ObjectType,
  Field,
} from '@nestjs/graphql';
import { IPv4AddressService } from './ipv4-address.service';
import { IPv4Address } from './ipv4-address.entity';
import {
  CreateIPv4AddressInput,
  UpdateIPv4AddressInput,
} from './ipv4-address.input';

@InputType()
export class SearchIPv4AddressInput extends PartialType(
  CreateIPv4AddressInput,
) {}
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

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
export class IPv4AddressResolver extends BaseStixResolver(IPv4Address) {
  public typeName = ' ipv4-addr';
  constructor(private readonly ipv4AddressService: IPv4AddressService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => IPv4Address)
  async createIPv4Address(
    @Args('input') createIPv4AddressInput: CreateIPv4AddressInput,
  ): Promise<IPv4Address> {
    return this.ipv4AddressService.create(createIPv4AddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => IPv4AddressSearchResult)
  async searchIPv4Addresses(
    @Args('filters', { type: () => SearchIPv4AddressInput, nullable: true })
    filters: SearchIPv4AddressInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IPv4AddressSearchResult> {
    return this.ipv4AddressService.searchWithFilters(filters, page, pageSize);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => IPv4Address, { nullable: true })
  async ipv4Address(@Args('id') id: string): Promise<IPv4Address> {
    return this.ipv4AddressService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [IPv4Address])
  async ipv4AddressesByValue(
    @Args('value') value: string,
  ): Promise<IPv4Address[]> {
    return this.ipv4AddressService.findByValue(value);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => IPv4Address)
  async updateIPv4Address(
    @Args('id') id: string,
    @Args('input') updateIPv4AddressInput: UpdateIPv4AddressInput,
  ): Promise<IPv4Address> {
    return this.ipv4AddressService.update(id, updateIPv4AddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteIPv4Address(@Args('id') id: string): Promise<boolean> {
    return this.ipv4AddressService.remove(id);
  }
}
