import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { NetworkTrafficService } from './network-traffic.service';
import { NetworkTraffic } from './network-traffic.entity';
import { CreateNetworkTrafficInput, UpdateNetworkTrafficInput } from './network-traffic.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchNetworkTrafficInput extends PartialType(CreateNetworkTrafficInput) {}

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
export class NetworkTrafficResolver {
  constructor(private readonly networkTrafficService: NetworkTrafficService) {}

  @Mutation(() => NetworkTraffic)
  async createNetworkTraffic(
    @Args('input') createNetworkTrafficInput: CreateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.create(createNetworkTrafficInput);
  }

  @Query(() => NetworkTrafficSearchResult)
  async searchNetworkTraffic(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchNetworkTrafficInput, nullable: true }) filters: SearchNetworkTrafficInput = {},
  ): Promise<NetworkTrafficSearchResult> {
    return this.networkTrafficService.searchWithFilters(from, size, filters);
  }

  @Query(() => NetworkTraffic, { nullable: true })
  async networkTraffic(@Args('id') id: string): Promise<NetworkTraffic> {
    return this.networkTrafficService.findOne(id);
  }

  @Mutation(() => NetworkTraffic)
  async updateNetworkTraffic(
    @Args('id') id: string,
    @Args('input') updateNetworkTrafficInput: UpdateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.update(id, updateNetworkTrafficInput);
  }

  @Mutation(() => Boolean)
  async deleteNetworkTraffic(@Args('id') id: string): Promise<boolean> {
    return this.networkTrafficService.remove(id);
  }
}