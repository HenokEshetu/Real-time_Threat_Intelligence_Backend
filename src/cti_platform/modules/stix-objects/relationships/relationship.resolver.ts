import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
} from '@nestjs/graphql';
import { RelationshipService } from './relationship.service';
import { StixRelationship } from './relationship.entity';
import {
  CreateRelationshipInput,
  UpdateRelationshipInput,
} from './relationship.input';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { StixObject } from '../stix-object.union';

@InputType()
export class SearchRelationshipInput extends PartialType(
  CreateRelationshipInput,
) {}

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
export class RelationshipResolver {
  constructor(private readonly relationshipService: RelationshipService) {}

  @Mutation(() => StixRelationship)
  async createRelationship(
    @Args('input') createRelationshipInput: CreateRelationshipInput,
  ): Promise<StixRelationship> {
    return this.relationshipService.create(createRelationshipInput);
  }

  @Query(() => StixRelationshipSearchResult)
  async searchRelationships(
    @Args('filters', { type: () => SearchRelationshipInput, nullable: true })
    filters: SearchRelationshipInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
    @Args('sortField', {
      type: () => String,
      defaultValue: 'modified',
      nullable: true,
    })
    sortField: keyof StixRelationship = 'modified',
    @Args('sortOrder', { type: () => String, defaultValue: 'desc' })
    sortOrder: 'asc' | 'desc' = 'desc',
  ): Promise<StixRelationshipSearchResult> {
    return this.relationshipService.searchWithFilters(
      filters,
      page,
      pageSize,
      sortField,
      sortOrder,
    );
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

  @Query(() => [StixObject], { name: 'getObjectsByIDs' })
  async getObjectsByIDs(
    @Args('ids', { type: () => [String] }) ids: string[],
  ): Promise<(typeof StixObject)[]> {
    return this.relationshipService.getObjectsByIds(ids);
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
