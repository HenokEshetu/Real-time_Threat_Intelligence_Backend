import { Resolver, InputType, Query, Mutation, Args } from '@nestjs/graphql';
import { EmailAddressService } from './email-address.service';
import { EmailAddress } from './email-address.entity';
import { CreateEmailAddressInput, UpdateEmailAddressInput } from './email-address.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchEmailAddressInput extends PartialType(CreateEmailAddressInput) {}


@Resolver(() => EmailAddress)
export class EmailAddressResolver {
  constructor(private readonly emailAddressService: EmailAddressService) {}
@Query(() => [EmailAddress])
async searchEmailAddress(
  @Args('filters', { type: () => SearchEmailAddressInput, nullable: true }) filters: Partial<SearchEmailAddressInput> = {}, // Accept dynamic filters
  @Args('page', { type: () => Number, defaultValue: 1 }) page: number = 1, // Pagination
  @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number = 10 // Pagination size
): Promise<EmailAddress[]> {
  return this.emailAddressService.searchWithFilters(filters, page, pageSize); // Pass filters, page, and pageSize
}
  @Query(() => EmailAddress)
  async emailAddress(@Args('id') id: string): Promise<EmailAddress> {
    return this.emailAddressService.findOne(id);
  }

  @Query(() => [EmailAddress])
  async emailAddressesByValue(@Args('value') value: string): Promise<EmailAddress[]> {
    return this.emailAddressService.findByValue(value);
  }

  @Query(() => [EmailAddress])
  async emailAddressesByDisplayName(@Args('displayName') displayName: string): Promise<EmailAddress[]> {
    return this.emailAddressService.findByDisplayName(displayName);
  }

  @Mutation(() => EmailAddress)
  async createEmailAddress(
    @Args('createEmailAddressInput') createEmailAddressInput: CreateEmailAddressInput,
  ): Promise<EmailAddress> {
    return this.emailAddressService.create(createEmailAddressInput);
  }

  @Mutation(() => EmailAddress)
  async updateEmailAddress(
    @Args('id') id: string,
    @Args('updateEmailAddressInput') updateEmailAddressInput: UpdateEmailAddressInput,
  ): Promise<EmailAddress> {
    return this.emailAddressService.update(id, updateEmailAddressInput);
  }

  @Mutation(() => Boolean)
  async removeEmailAddress(@Args('id') id: string): Promise<boolean> {
    return this.emailAddressService.remove(id);
  }
}