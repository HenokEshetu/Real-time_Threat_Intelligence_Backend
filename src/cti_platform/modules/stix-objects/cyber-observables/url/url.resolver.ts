import { Resolver,InputType, Query, Mutation, Args } from '@nestjs/graphql';
import { UrlService } from './url.service';
import { Url } from './url.entity';
import { CreateUrlInput, UpdateUrlInput } from './url.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchUrlInput extends PartialType(CreateUrlInput) {}


@Resolver(() => Url)
export class UrlResolver {
  constructor(private readonly urlService: UrlService) {}

  @Query(() =>Url, { description: 'Search URLs with dynamic filters and pagination' })
  async searchUrlsWithFilters(
    @Args('searchParams', { type: () => SearchUrlInput, nullable: true }) searchParams?: Partial<SearchUrlInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number
  ): Promise<any> {
    return this.urlService.searchWithFilters(searchParams || {}, page, pageSize);
  }
  @Query(() => Url)
  async url(@Args('id') id: string): Promise<Url> {
    return this.urlService.findOne(id);
  }

  @Mutation(() => Url)
  async createUrl(
    @Args('createUrlInput') createUrlInput: CreateUrlInput,
  ): Promise<Url> {
    return this.urlService.create(createUrlInput);
  }

  @Mutation(() => Url)
  async updateUrl(
    @Args('id') id: string,
    @Args('updateUrlInput') updateUrlInput: UpdateUrlInput,
  ): Promise<Url> {
    return this.urlService.update(id, updateUrlInput);
  }

  @Mutation(() => Boolean)
  async removeUrl(@Args('id') id: string): Promise<boolean> {
    return this.urlService.remove(id);
  }
}