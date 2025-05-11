import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { IdentityService } from './identity.service';
import { Identity } from './identity.entity';
import { CreateIdentityInput, UpdateIdentityInput } from './identity.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';

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
export class IdentityResolver  {
        constructor(
          private readonly identityService: IdentityService,
          @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
        ) { }
      
        // Date conversion helper
        public convertDates(payload: any): Identity {
          const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
          dateFields.forEach(field => {
            if (payload[field]) payload[field] = new Date(payload[field]);
          });
          return payload;
        }
      
        // Subscription Definitions
        @Subscription(() => Identity, {
          name: 'identityCreated',
          resolve: (payload) => payload,
        })
        identityCreated() {
          return this.pubSub.asyncIterator('identityCreated');
        }
      
        @Subscription(() => Identity, {
          name: 'identityUpdated',
          resolve: (payload) => payload,
        })
        identityUpdated() {
          return this.pubSub.asyncIterator('identityUpdated');
        }
      
        @Subscription(() => String, { name: 'identityDeleted' })
        identityDeleted() {
          return this.pubSub.asyncIterator('identityDeleted');
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