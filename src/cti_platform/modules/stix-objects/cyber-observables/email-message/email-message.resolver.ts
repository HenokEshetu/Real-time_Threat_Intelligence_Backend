import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { EmailMessageService } from './email-message.service';
import { EmailMessage } from './email-message.entity';
import { CreateEmailMessageInput, UpdateEmailMessageInput } from './email-message.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchEmailMessageInput extends PartialType(CreateEmailMessageInput) {}


@Resolver(() => EmailMessage)
export class EmailMessageResolver {
  constructor(private readonly emailMessageService: EmailMessageService) {}

  

  @Query(() => EmailMessage)
  async emailMessage(@Args('id') id: string): Promise<EmailMessage> {
    return this.emailMessageService.findOne(id);
  }

  @Mutation(() => EmailMessage)
  async createEmailMessage(
    @Args('createEmailMessageInput') createEmailMessageInput: CreateEmailMessageInput,
  ): Promise<EmailMessage> {
    return this.emailMessageService.create(createEmailMessageInput);
  }

  @Mutation(() => EmailMessage)
  async updateEmailMessage(
    @Args('id') id: string,
    @Args('updateEmailMessageInput') updateEmailMessageInput: UpdateEmailMessageInput,
  ): Promise<EmailMessage> {
    return this.emailMessageService.update(id, updateEmailMessageInput);
  }

  @Mutation(() => Boolean)
  async removeEmailMessage(@Args('id') id: string): Promise<boolean> {
    await this.emailMessageService.remove(id);
    return true;
  }



  @Query(() => [EmailMessage])
  async searchEmailMessage(
    @Args('filters', { type: () => SearchEmailMessageInput, nullable: true }) filters: Partial<SearchEmailMessageInput> = {}, // Accept dynamic filters
    @Args('page', { type: () => Number, defaultValue: 1 }) page: number = 1, // Pagination
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number = 10 // Pagination size
  ): Promise<EmailMessage[]> {
    return this.emailMessageService.searchWithFilters(filters, page, pageSize); // Pass filters, page, and pageSize

}}