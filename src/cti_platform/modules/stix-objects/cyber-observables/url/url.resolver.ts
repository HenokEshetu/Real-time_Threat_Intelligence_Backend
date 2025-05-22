import {
  Resolver,
  InputType,
  Query,
  Mutation,
  Args,
  Int,
  ObjectType,
  Field,
  PartialType,
} from '@nestjs/graphql';
import { UrlService } from './url.service';
import { Url } from './url.entity';
import { CreateUrlInput, UpdateUrlInput } from './url.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

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
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => Url)
  async createUrl(@Args('input') createUrlInput: CreateUrlInput): Promise<Url> {
    return this.urlService.create(createUrlInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => UrlSearchResult)
  async searchUrls(
    @Args('filters', { type: () => SearchUrlInput, nullable: true })
    filters: SearchUrlInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<UrlSearchResult> {
    return this.urlService.searchWithFilters(filters, page, pageSize);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => Url, { nullable: true })
  async url(@Args('id') id: string): Promise<Url> {
    return this.urlService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => Url)
  async updateUrl(
    @Args('id') id: string,
    @Args('input') updateUrlInput: UpdateUrlInput,
  ): Promise<Url> {
    return this.urlService.update(id, updateUrlInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteUrl(@Args('id') id: string): Promise<boolean> {
    return this.urlService.remove(id);
  }
}
