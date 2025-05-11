import { Resolver, Query,InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { RelationshipService } from './relationship.service';
import { StixRelationship } from './relationship.entity';
import { CreateRelationshipInput, UpdateRelationshipInput } from './relationship.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';


@InputType()
export class SearchRelationshipInput extends PartialType(CreateRelationshipInput){}


@ObjectType()
export class StixRelationshipSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [StixRelationship])
  results: StixRelationship[];
}

@Resolver(() => StixRelationship)
export class RelationshipResolver  {
  
  
  constructor(
    private readonly relationshipService: RelationshipService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }
  // Date conversion helper
  public convertDates(payload: any): StixRelationship {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }
  // Subscription Definitions
  @Subscription(() => StixRelationship, {
    name: 'relationshipCreated',
    resolve: (payload) => payload,
  })
  relationshipCreated() {
    return this.pubSub.asyncIterator('relationshipCreated');
  }
  @Subscription(() => StixRelationship, {
    name: 'relationshipUpdated',
    resolve: (payload) => payload,
  })
  relationshipUpdated() {
    return this.pubSub.asyncIterator('relationshipUpdated');
  }
  @Subscription(() => StixRelationship, {
    name: 'relationshipDeleted',
    resolve: (payload) => payload,
  })
  relationshipDeleted() {
    return this.pubSub.asyncIterator('relationshipDeleted');
  } 

  @Mutation(() => StixRelationship)
  async createRelationship(
    @Args('input') createRelationshipInput: CreateRelationshipInput,
  ): Promise<StixRelationship> {
    return this.relationshipService.create(createRelationshipInput);
  }

  @Query(() => StixRelationshipSearchResult)
  async searchRelationships(
    @Args('filters', { type: () => SearchRelationshipInput, nullable: true }) filters: SearchRelationshipInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
    @Args('sortField', { type: () => String, defaultValue: 'modified', nullable: true }) sortField: keyof StixRelationship = 'modified',
    @Args('sortOrder', { type: () => String, defaultValue: 'desc' }) sortOrder: 'asc' | 'desc' = 'desc',
  ): Promise<StixRelationshipSearchResult> {
    return this.relationshipService.searchWithFilters(filters, page, pageSize, sortField, sortOrder);
  }

  @Query(() => StixRelationship, { nullable: true })
  async relationship(@Args('id') id: string): Promise<StixRelationship> {
    return this.relationshipService.findOne(id);
  }

  @Query(() => [StixRelationship])
  async relatedRelationships(
    @Args('objectId') objectId: string,
  ): Promise<StixRelationship[]> {
    return this.relationshipService.findRelatedObjects(objectId);
  }

  @Query(() => [StixRelationship], { nullable: true })
  async expandedRelatedObjects(
    @Args('objectId') objectId: string,
  ): Promise<any[]> {
    return this.relationshipService.findExpandedRelatedObjects(objectId);
  }

  @Mutation(() => StixRelationship)
  async updateRelationship(
    @Args('id') id: string,
    @Args('input') updateRelationshipInput: UpdateRelationshipInput,
  ): Promise<StixRelationship> {
    return this.relationshipService.update(id, updateRelationshipInput);
  }

  @Mutation(() => Boolean)
  async deleteRelationship(@Args('id') id: string): Promise<boolean> {
    return this.relationshipService.remove(id);
  }
}