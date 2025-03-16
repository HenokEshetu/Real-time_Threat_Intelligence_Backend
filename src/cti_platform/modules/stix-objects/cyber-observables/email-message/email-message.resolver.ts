import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { EmailMessageService } from './email-message.service';
import { EmailMessage } from './email-message.entity';
import { CreateEmailMessageInput, UpdateEmailMessageInput } from './email-message.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchEmailMessageInput extends PartialType(CreateEmailMessageInput) {}


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
export class EmailMessageResolver {
  constructor(private readonly emailMessageService: EmailMessageService) {}

  @Mutation(() => EmailMessage)
  async createEmailMessage(
    @Args('input') createEmailMessageInput: CreateEmailMessageInput,
  ): Promise<EmailMessage> {
    return this.emailMessageService.create(createEmailMessageInput);
  }

  @Query(() => EmailMessageSearchResult)
  async searchEmailMessages(
    @Args('filters', { type: () => SearchEmailMessageInput, nullable: true }) filters: SearchEmailMessageInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<EmailMessageSearchResult> {
    return this.emailMessageService.searchWithFilters(filters, from, size);
  }

  @Query(() => EmailMessage, { nullable: true })
  async emailMessage(@Args('id') id: string): Promise<EmailMessage> {
    return this.emailMessageService.findByID(id);
  }

  @Mutation(() => EmailMessage)
  async updateEmailMessage(
    @Args('id') id: string,
    @Args('input') updateEmailMessageInput: UpdateEmailMessageInput,
  ): Promise<EmailMessage> {
    return this.emailMessageService.update(id, updateEmailMessageInput);
  }

  @Mutation(() => Boolean)
  async deleteEmailMessage(@Args('id') id: string): Promise<boolean> {
    return this.emailMessageService.remove(id);
  }
}