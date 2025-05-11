import { Resolver, InputType, Query, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { EmailAddressService } from './email-address.service';
import { EmailAddress } from './email-address.entity';
import { CreateEmailAddressInput, UpdateEmailAddressInput } from './email-address.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';
@InputType()
export class SearchEmailAddressInput extends PartialType(CreateEmailAddressInput) {}




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
export class EmailAddressResolver  {
 
  constructor(
              private readonly emailAddressService: EmailAddressService,
                @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
              ) {}
            
              // Date conversion helper
              public convertDates(payload: any): EmailAddress {
                const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
                dateFields.forEach(field => {
                  if (payload[field]) payload[field] = new Date(payload[field]);
                });
                return payload;
              }
            
              // Subscription Definitions
              @Subscription(() => EmailAddress, {
                name: 'emailAddrCreated',
                resolve: (payload) => payload,
              })
              emailAddrCreated() {
                return this.pubSub.asyncIterator('emailAddressCreated');
              }
            
              @Subscription(() => EmailAddress, {
                name: 'emailAddressUpdated',
                resolve: (payload) => payload,
              })
              emailAddrUpdated() {
                return this.pubSub.asyncIterator('emailAddressUpdated');
              }
            
              @Subscription(() => String, { name: 'emailAddressDeleted' })
              emailAddrDeleted() {
                return this.pubSub.asyncIterator('emailAddressDeleted');
              }

  @Mutation(() => EmailAddress)
  async createEmailAddress(
    @Args('input') createEmailAddressInput: CreateEmailAddressInput,
  ): Promise<EmailAddress> {
    return this.emailAddressService.create(createEmailAddressInput);
  }

  @Query(() => EmailAddressSearchResult)
  async searchEmailAddresses(
    @Args('filters', { type: () => SearchEmailAddressInput, nullable: true }) filters: SearchEmailAddressInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<EmailAddressSearchResult> {
    return this.emailAddressService.searchWithFilters(filters, from, size);
  }

  @Query(() => EmailAddress, { nullable: true })
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
  async updateEmailAddress(
    @Args('id') id: string,
    @Args('input') updateEmailAddressInput: UpdateEmailAddressInput,
  ): Promise<EmailAddress> {
    return this.emailAddressService.update(id, updateEmailAddressInput);
  }

  @Mutation(() => Boolean)
  async deleteEmailAddress(@Args('id') id: string): Promise<boolean> {
    return this.emailAddressService.remove(id);
  }
}