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
import { MACAddressService } from './mac-address.service';
import { MACAddress } from './mac-address.entity';
import {
  CreateMACAddressInput,
  UpdateMACAddressInput,
} from './mac-address.input';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchMACAddressInput extends PartialType(CreateMACAddressInput) {}

@ObjectType()
export class MACAddressSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [MACAddress])
  results: MACAddress[];
}

@Resolver(() => MACAddress)
export class MACAddressResolver {
  constructor(private readonly macAddressService: MACAddressService) {}

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => MACAddress)
  async createMACAddress(
    @Args('input') createMACAddressInput: CreateMACAddressInput,
  ): Promise<MACAddress> {
    return this.macAddressService.create(createMACAddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => MACAddressSearchResult)
  async searchMACAddresses(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filter', { type: () => SearchMACAddressInput, nullable: true })
    filter: SearchMACAddressInput = {},
  ): Promise<MACAddressSearchResult> {
    return this.macAddressService.searchWithFilters(from, size, filter);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => MACAddress, { nullable: true })
  async macAddress(@Args('id') id: string): Promise<MACAddress> {
    return this.macAddressService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Mutation(() => MACAddress)
  async updateMACAddress(
    @Args('id') id: string,
    @Args('input') updateMACAddressInput: UpdateMACAddressInput,
  ): Promise<MACAddress> {
    return this.macAddressService.update(id, updateMACAddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Mutation(() => Boolean)
  async deleteMACAddress(@Args('id') id: string): Promise<boolean> {
    return this.macAddressService.remove(id);
  }
}
