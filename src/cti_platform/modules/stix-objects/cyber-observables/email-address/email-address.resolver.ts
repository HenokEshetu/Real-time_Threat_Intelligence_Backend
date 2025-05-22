import {
  Resolver,
  InputType,
  Query,
  Mutation,
  Args,
  Int,
} from '@nestjs/graphql';
import { EmailAddressService } from './email-address.service';
import { EmailAddress } from './email-address.entity';
import {
  CreateEmailAddressInput,
  UpdateEmailAddressInput,
} from './email-address.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchEmailAddressInput extends PartialType(
  CreateEmailAddressInput,
) {}

@ObjectType()
export class EmailAddressSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [EmailAddress])
  results: EmailAddress[];
}

@Resolver(() => EmailAddress)
export class EmailAddressResolver extends BaseStixResolver(EmailAddress) {
  public typeName = 'directory';
  constructor(private readonly emailAddressService: EmailAddressService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => EmailAddress)
  async createEmailAddress(
    @Args('input') createEmailAddressInput: CreateEmailAddressInput,
  ): Promise<EmailAddress> {
    return this.emailAddressService.create(createEmailAddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => EmailAddressSearchResult)
  async searchEmailAddresses(
    @Args('filters', { type: () => SearchEmailAddressInput, nullable: true })
    filters: SearchEmailAddressInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<EmailAddressSearchResult> {
    return this.emailAddressService.searchWithFilters(filters, from, size);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => EmailAddress, { nullable: true })
  async emailAddress(@Args('id') id: string): Promise<EmailAddress> {
    return this.emailAddressService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [EmailAddress])
  async emailAddressesByValue(
    @Args('value') value: string,
  ): Promise<EmailAddress[]> {
    return this.emailAddressService.findByValue(value);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [EmailAddress])
  async emailAddressesByDisplayName(
    @Args('displayName') displayName: string,
  ): Promise<EmailAddress[]> {
    return this.emailAddressService.findByDisplayName(displayName);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => EmailAddress)
  async updateEmailAddress(
    @Args('id') id: string,
    @Args('input') updateEmailAddressInput: UpdateEmailAddressInput,
  ): Promise<EmailAddress> {
    return this.emailAddressService.update(id, updateEmailAddressInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteEmailAddress(@Args('id') id: string): Promise<boolean> {
    return this.emailAddressService.remove(id);
  }
}
