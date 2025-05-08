import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { IdentityService } from './identity.service';
import { Identity } from './identity.entity';
import { CreateIdentityInput, UpdateIdentityInput } from './identity.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

@InputType()
export class SearchIdentityInput extends PartialType(CreateIdentityInput){}

@ObjectType()
export class IdentitySearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Identity])
  results: Identity[];
}

@Resolver(() => Identity)
export class IdentityResolver extends BaseStixResolver(Identity) {
  public typeName = 'identity';
  constructor(private readonly identityService: IdentityService) {

    super();
  }

  @Mutation(() => Identity)
  async createIdentity(
    @Args('input') createIdentityInput: CreateIdentityInput,
  ): Promise<Identity> {
    return this.identityService.create(createIdentityInput);
  }

  @Query(() => IdentitySearchResult)
  async searchIdentities(
    @Args('filters', { type: () => SearchIdentityInput, nullable: true }) filters: SearchIdentityInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IdentitySearchResult> {
    return this.identityService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Identity, { nullable: true })
  async identity(@Args('id') id: string): Promise<Identity> {
    return this.identityService.findOne(id);
  }

  @Mutation(() => Identity)
  async updateIdentity(
    @Args('id') id: string,
    @Args('input') updateIdentityInput: UpdateIdentityInput,
  ): Promise<Identity> {
    return this.identityService.update(id, updateIdentityInput);
  }

  @Mutation(() => Boolean)
  async deleteIdentity(@Args('id') id: string): Promise<boolean> {
    return this.identityService.remove(id);
  }
}