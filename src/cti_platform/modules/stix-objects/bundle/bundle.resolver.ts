import {
  Resolver,
  InputType,
  Query,
  Int,
  Mutation,
  ObjectType,
  Field,
  Args,
} from '@nestjs/graphql';
import { BundleService } from './bundle.service';
import { Bundle } from './bundle.entity';
import { CreateBundleInput, UpdateBundleInput } from './bundle.input';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchBundleInput extends PartialType(CreateBundleInput) {}

@ObjectType()
export class SearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [Bundle])
  results: Bundle[];
}

@Resolver(() => Bundle)
export class BundleResolver extends BaseStixResolver(Bundle) {
  public typeName = 'bundle';
  constructor(private readonly bundleService: BundleService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => Bundle)
  async createBundle(@Args('input') input: CreateBundleInput): Promise<Bundle> {
    return this.bundleService.create(input);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => Bundle, { nullable: true })
  async bundle(
    @Args('id', { type: () => String }) id: string,
  ): Promise<Bundle> {
    return this.bundleService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => SearchResult)
  async searchBundles(
    @Args('filters', { type: () => SearchBundleInput, nullable: true })
    filters: SearchBundleInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<SearchResult> {
    return this.bundleService.searchWithFilters(filters, page, pageSize);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => Bundle)
  async updateBundle(
    @Args('id', { type: () => String }) id: string,
    @Args('input') input: UpdateBundleInput,
  ): Promise<Bundle> {
    return this.bundleService.update(id, input);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteBundle(
    @Args('id', { type: () => String }) id: string,
  ): Promise<boolean> {
    return this.bundleService.remove(id);
  }
}
