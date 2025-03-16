import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { NetworkTrafficService } from './network-traffic.service';
import { NetworkTraffic } from './network-traffic.entity';
import { CreateNetworkTrafficInput, UpdateNetworkTrafficInput } from './network-traffic.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchNetworkTrafficInput extends PartialType(CreateNetworkTrafficInput) {}



@Resolver(() => NetworkTraffic)
export class NetworkTrafficResolver {
  constructor(private readonly networkTrafficService: NetworkTrafficService) {}

  @Mutation(() => NetworkTraffic)
  async createNetworkTraffic(
    @Args('createNetworkTrafficInput') createNetworkTrafficInput: CreateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.create(createNetworkTrafficInput);
  }

  // Search network traffic dynamically using filters
  @Query(() => [NetworkTraffic], { name: 'network_traffic' })
  async searchNetworkTraffic(
    @Args('from', { type: () => Number, nullable: true }) from?: number,
    @Args('size', { type: () => Number, nullable: true }) size?: number,
    @Args('filter', { type: () => SearchNetworkTrafficInput, nullable: true }) filter?: SearchNetworkTrafficInput,
  ): Promise<NetworkTraffic[]> {
    return this.networkTrafficService.searchWithFilters(from ?? 0, size ?? 10, filter ?? {});
  }
  

  @Query(() => NetworkTraffic)
  async networkTraffic(@Args('id') id: string): Promise<NetworkTraffic> {
    return this.networkTrafficService.findOne(id);
  }

  @Mutation(() => NetworkTraffic)
  async updateNetworkTraffic(
    @Args('id') id: string,
    @Args('updateNetworkTrafficInput') updateNetworkTrafficInput: UpdateNetworkTrafficInput,
  ): Promise<NetworkTraffic> {
    return this.networkTrafficService.update(id, updateNetworkTrafficInput);
  }

  @Mutation(() => Boolean)
  async removeNetworkTraffic(@Args('id') id: string): Promise<boolean> {
    return this.networkTrafficService.remove(id);
  }
}