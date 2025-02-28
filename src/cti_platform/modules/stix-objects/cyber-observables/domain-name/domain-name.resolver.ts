import { Resolver, Query, Mutation,InputType, Args } from '@nestjs/graphql';
import { DomainNameService } from './domain-name.service';
import { DomainName } from './domain-name.entity';
import { CreateDomainNameInput, UpdateDomainNameInput } from './domain-name.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchDomainNameInput extends PartialType(CreateDomainNameInput) {}


@Resolver(() => DomainName)
export class DomainNameResolver {
  constructor(private readonly domainNameService: DomainNameService) {}

  @Query(() => [DomainName])
async domainNames(
  @Args('filters', { type: () =>SearchDomainNameInput, nullable: true }) filters: Partial<SearchDomainNameInput> = {}, // Accept dynamic filters
  @Args('page', { type: () => Number, defaultValue: 1 }) page: number = 1, // Pagination
  @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number = 10 // Pagination size
): Promise<DomainName[]> {
  return this.domainNameService.searchWithFilters(filters, page, pageSize); // Pass filters, page, and pageSize
}

  @Query(() => DomainName)
  async domainName(@Args('id') id: string): Promise<DomainName> {
    return this.domainNameService.findOne(id);
  }

  @Query(() => [DomainName])
  async domainNamesByValue(@Args('value') value: string): Promise<DomainName[]> {
    return this.domainNameService.findByValue(value);
  }

  @Mutation(() => DomainName)
  async createDomainName(
    @Args('createDomainNameInput') createDomainNameInput: CreateDomainNameInput,
  ): Promise<DomainName> {
    return this.domainNameService.create(createDomainNameInput);
  }

  @Mutation(() => DomainName)
  async updateDomainName(
    @Args('id') id: string,
    @Args('updateDomainNameInput') updateDomainNameInput: UpdateDomainNameInput,
  ): Promise<DomainName> {
    return this.domainNameService.update(id, updateDomainNameInput);
  }

  @Mutation(() => Boolean)
  async removeDomainName(@Args('id') id: string): Promise<boolean> {
    return this.domainNameService.remove(id);
  }
  
}