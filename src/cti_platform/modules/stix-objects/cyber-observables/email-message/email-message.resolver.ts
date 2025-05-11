import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { EmailMessage } from './email-message.entity';
import { CreateEmailMessageInput, UpdateEmailMessageInput } from './email-message.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { EmailMessageService } from './email-message.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchEmailMessageInput extends PartialType(CreateEmailMessageInput) { }


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

  constructor(
    private readonly emailMessageService: EmailMessageService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): EmailMessage {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => EmailMessage, {
    name: 'emailMessageCreated',
    resolve: (payload) => payload,
  })
  indicatorCreated() {
    return this.pubSub.asyncIterator('emailMessageCreated');
  }

  @Subscription(() => EmailMessage, {
    name: 'emailMessageUpdated',
    resolve: (payload) => payload,
  })
  indicatorUpdated() {
    return this.pubSub.asyncIterator('emailMessageUpdated');
  }

  @Subscription(() => String, { name: 'emailMessageDeleted' })
  indicatorDeleted() {
    return this.pubSub.asyncIterator('emailMessageDeleted');
  }

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
    return this.emailMessageService.findOne(id);
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