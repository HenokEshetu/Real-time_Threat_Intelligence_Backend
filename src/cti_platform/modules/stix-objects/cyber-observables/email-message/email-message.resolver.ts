import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
} from '@nestjs/graphql';
import { EmailMessageService } from './email-message.service';
import { EmailMessage } from './email-message.entity';
import {
  CreateEmailMessageInput,
  UpdateEmailMessageInput,
} from './email-message.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchEmailMessageInput extends PartialType(
  CreateEmailMessageInput,
) {}

@ObjectType()
export class EmailMessageSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [EmailMessage])
  results: EmailMessage[];
}

@Resolver(() => EmailMessage)
export class EmailMessageResolver extends BaseStixResolver(EmailMessage) {
  public typeName = 'email-message';
  constructor(private readonly emailMessageService: EmailMessageService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => EmailMessage)
  async createEmailMessage(
    @Args('input') createEmailMessageInput: CreateEmailMessageInput,
  ): Promise<EmailMessage> {
    return this.emailMessageService.create(createEmailMessageInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => EmailMessageSearchResult)
  async searchEmailMessages(
    @Args('filters', { type: () => SearchEmailMessageInput, nullable: true })
    filters: SearchEmailMessageInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<EmailMessageSearchResult> {
    return this.emailMessageService.searchWithFilters(filters, from, size);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => EmailMessage, { nullable: true })
  async emailMessage(@Args('id') id: string): Promise<EmailMessage> {
    return this.emailMessageService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => EmailMessage)
  async updateEmailMessage(
    @Args('id') id: string,
    @Args('input') updateEmailMessageInput: UpdateEmailMessageInput,
  ): Promise<EmailMessage> {
    return this.emailMessageService.update(id, updateEmailMessageInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteEmailMessage(@Args('id') id: string): Promise<boolean> {
    return this.emailMessageService.remove(id);
  }
}
