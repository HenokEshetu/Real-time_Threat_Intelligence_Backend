import { Resolver,InputType, Query, Mutation, Args,Int } from '@nestjs/graphql';
import { UrlService } from './url.service';
import { Url } from './url.entity';
import { CreateUrlInput, UpdateUrlInput } from './url.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
@InputType()
export class SearchUrlInput extends PartialType(CreateUrlInput) {}




@ObjectType()
export class UrlSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Url])
  results: Url[];
}

@Resolver(() => Url)
export class UrlResolver extends BaseStixResolver(Url) {
  public typeName = ' url';
  constructor(private readonly urlService: UrlService) {
    super()
  }

  @Mutation(() => Url)
  async createUrl(
    @Args('input') createUrlInput: CreateUrlInput,
  ): Promise<Url> {
    return this.urlService.create(createUrlInput);
  }

  @Query(() => UrlSearchResult)
  async searchUrls(
    @Args('filters', { type: () => SearchUrlInput, nullable: true }) filters: SearchUrlInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<UrlSearchResult> {
    return this.urlService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Url, { nullable: true })
  async url(@Args('id') id: string): Promise<Url> {
    return this.urlService.findOne(id);
  }

  @Mutation(() => Url)
  async updateUrl(
    @Args('id') id: string,
    @Args('input') updateUrlInput: UpdateUrlInput,
  ): Promise<Url> {
    return this.urlService.update(id, updateUrlInput);
  }

  @Mutation(() => Boolean)
  async deleteUrl(@Args('id') id: string): Promise<boolean> {
    return this.urlService.remove(id);
  }
}