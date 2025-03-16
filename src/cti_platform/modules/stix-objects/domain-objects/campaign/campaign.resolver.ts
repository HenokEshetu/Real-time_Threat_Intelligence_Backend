import { Resolver, Query,InputType, Int, Mutation, Args } from '@nestjs/graphql';
import { CampaignService } from './campaign.service';
import { Campaign } from './campaign.entity';
import { CreateCampaignInput, UpdateCampaignInput } from './campaign.input';



import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchCampaignInput extends PartialType(CreateCampaignInput){}


@Resolver(() => Campaign)
export class CampaignResolver {
  constructor(private readonly campaignService: CampaignService) {}

  //  Create Attack Pattern
    @Mutation(() => Campaign)
    async createCampaign(
      @Args('input') input: CreateCampaignInput,
    ): Promise<Campaign> {
      return this.campaignService.create(input);
    }
  
    //  Find one Attack Pattern by ID
    @Query(() => Campaign, { nullable: true })
    async Campaign(@Args('id') id: string): Promise<Campaign> {
      return this.campaignService.findOne(id);
    }
  
    //  Update Attack Pattern
    @Mutation(() => Campaign)
    async updateCampaign(
      @Args('id') id: string,
      @Args('input') input: UpdateCampaignInput,
    ): Promise<Campaign> {
      return this.campaignService.update(id, input);
    }
  
    // Delete Attack Pattern
    @Mutation(() => Boolean)
    async removeCampaign(@Args('id') id: string): Promise<boolean> {
      return this.campaignService.remove(id);
    }
  
    // Search Attack Patterns with filters & pagination
    @Query(() => [Campaign])
    async searchCampaign(
      @Args('filters', { type: () => SearchCampaignInput, nullable: true }) filters: Partial<SearchCampaignInput>,
      @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
      @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
    ): Promise<{ total: number; results: Campaign[] }> {
      return this.campaignService.searchWithFilters(filters, page, pageSize);
    }
}