import {
  Resolver,
  Query,
  Mutation,
  InputType,
  Args,
  Int,
} from '@nestjs/graphql';
import { DomainNameService } from './domain-name.service';
import { DomainName } from './domain-name.entity';
import {
  CreateDomainNameInput,
  UpdateDomainNameInput,
} from './domain-name.input';
import { PartialType, ObjectType, Field } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchDomainNameInput extends PartialType(CreateDomainNameInput) {}

@ObjectType()
export class DomainNameSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [DomainName])
  results: DomainName[];
}

@Resolver(() => DomainName)
export class DomainNameResolver extends BaseStixResolver(DomainName) {
  public typeName = 'directory';
  constructor(private readonly domainNameService: DomainNameService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => DomainName)
  async createDomainName(
    @Args('input') createDomainNameInput: CreateDomainNameInput,
  ): Promise<DomainName> {
    return this.domainNameService.create(createDomainNameInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => DomainNameSearchResult)
  async searchDomainNames(
    @Args('filters', { type: () => SearchDomainNameInput, nullable: true })
    filters: SearchDomainNameInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<DomainNameSearchResult> {
    return this.domainNameService.searchWithFilters(filters, page, pageSize);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => DomainName, { nullable: true })
  async domainName(@Args('id') id: string): Promise<DomainName> {
    return this.domainNameService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [DomainName])
  async domainNamesByValue(
    @Args('value') value: string,
  ): Promise<DomainName[]> {
    return this.domainNameService.findByValue(value);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => DomainName)
  async updateDomainName(
    @Args('id') id: string,
    @Args('input') updateDomainNameInput: UpdateDomainNameInput,
  ): Promise<DomainName> {
    return this.domainNameService.update(id, updateDomainNameInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteDomainName(@Args('id') id: string): Promise<boolean> {
    return this.domainNameService.remove(id);
  }
}
