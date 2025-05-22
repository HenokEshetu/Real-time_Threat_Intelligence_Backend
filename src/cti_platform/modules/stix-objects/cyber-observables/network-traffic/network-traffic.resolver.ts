import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
  ObjectType,
  Field,
  PartialType,
} from '@nestjs/graphql';
import { NetworkTrafficService } from './network-traffic.service';
import { NetworkTraffic } from './network-traffic.entity';
import {
  CreateNetworkTrafficInput,
  UpdateNetworkTrafficInput,
} from './network-traffic.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchNetworkTrafficInput extends PartialType(
  CreateNetworkTrafficInput,
) {}

@ObjectType()
export class NetworkTrafficSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [NetworkTraffic])
  results: NetworkTraffic[];
}

@Resolver(() => NetworkTraffic)
export class NetworkTrafficResolver extends BaseStixResolver(NetworkTraffic) {
  public typeName = ' network-traffic';
  constructor(private readonly networkTrafficService: NetworkTrafficService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => NetworkTraffic)
  async createNetworkTraffic(
    @Args('input') createNetworkTrafficInput: CreateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.create(createNetworkTrafficInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => NetworkTrafficSearchResult)
  async searchNetworkTraffic(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchNetworkTrafficInput, nullable: true })
    filters: SearchNetworkTrafficInput = {},
  ): Promise<NetworkTrafficSearchResult> {
    return this.networkTrafficService.searchWithFilters(from, size, filters);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => NetworkTraffic, { nullable: true })
  async networkTraffic(@Args('id') id: string): Promise<NetworkTraffic> {
    return this.networkTrafficService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => NetworkTraffic)
  async updateNetworkTraffic(
    @Args('id') id: string,
    @Args('input') updateNetworkTrafficInput: UpdateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.update(id, updateNetworkTrafficInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteNetworkTraffic(@Args('id') id: string): Promise<boolean> {
    return this.networkTrafficService.remove(id);
  }
}
