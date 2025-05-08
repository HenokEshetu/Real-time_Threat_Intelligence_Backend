import { Resolver, Query,InputType, Int, Mutation, Args } from '@nestjs/graphql';
import { CampaignService } from './campaign.service';
import { Campaign } from './campaign.entity';
import { CreateCampaignInput, UpdateCampaignInput } from './campaign.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

@InputType()
export class SearchCampaignInput extends PartialType(CreateCampaignInput){}

@ObjectType()
export class CampaignSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Campaign])
  results: Campaign[];
}

@Resolver(() => Campaign)
export class CampaignResolver extends BaseStixResolver(Campaign) {
  public typeName = 'campaign';
  constructor(private readonly campaignService: CampaignService) {
    super();
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