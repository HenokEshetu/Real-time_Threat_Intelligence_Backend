import { Resolver, Query,InputType, Int, Mutation, Args, Subscription } from '@nestjs/graphql';
import { CampaignService } from './campaign.service';
import { Campaign } from './campaign.entity';
import { CampaignSearchResult, CreateCampaignInput, SearchCampaignInput, UpdateCampaignInput } from './campaign.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';





@Resolver(() => Campaign)
export class CampaignResolver  {
  
  constructor(
      private readonly campaignService: CampaignService,
      @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
    ) { }
  
    // Date conversion helper
    public convertDates(payload: any): Campaign {
      const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
      dateFields.forEach(field => {
        if (payload[field]) payload[field] = new Date(payload[field]);
      });
      return payload;
    }
  
    // Subscription Definitions
    @Subscription(() => Campaign, {
      name: 'campaignCreated',
      resolve: (payload) => payload,
    })
    campaignCreated() {
      return this.pubSub.asyncIterator('campaignCreated');
    }
  
    @Subscription(() => Campaign, {
      name: 'campaignUpdated',
      resolve: (payload) => payload,
    })
    campaignUpdated() {
      return this.pubSub.asyncIterator('campaignUpdated');
    }
  
    @Subscription(() => String, { name: 'campaignDeleted' })
    campaignDeleted() {
      return this.pubSub.asyncIterator('campaignDeleted');
    }
    
  

  @Mutation(() => Campaign)
  async createCampaign(
    @Args('input') createCampaignInput: CreateCampaignInput,
  ): Promise<Campaign> {
    return this.campaignService.create(createCampaignInput);
  }

  @Query(() => CampaignSearchResult)
  async searchCampaigns(
    @Args('filters', { type: () => SearchCampaignInput, nullable: true }) filters: SearchCampaignInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<CampaignSearchResult> {
    return this.campaignService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Campaign, { nullable: true })
  async campaign(@Args('id') id: string): Promise<Campaign> {
    return this.campaignService.findOne(id);
  }

  @Mutation(() => Campaign)
  async updateCampaign(
    @Args('id') id: string,
    @Args('input') updateCampaignInput: UpdateCampaignInput,
  ): Promise<Campaign> {
    return this.campaignService.update(id, updateCampaignInput);
  }

  @Mutation(() => Boolean)
  async deleteCampaign(@Args('id') id: string): Promise<boolean> {
    return this.campaignService.remove(id);
  }
}