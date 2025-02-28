import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { RelationshipService } from './relationship.service';
import { StixRelationship } from './relationship.entity';
import { CreateRelationshipInput, UpdateRelationshipInput } from './relationship.input';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchRelationshipInput extends PartialType(CreateRelationshipInput){}




@Resolver(() => StixRelationship)
export class RelationshipResolver {
  constructor(private readonly relationshipService: RelationshipService) {}

  @Mutation(() => StixRelationship)
  async createRelationship(
    @Args('createRelationshipInput') createRelationshipInput: CreateRelationshipInput
  ): Promise<StixRelationship> {
    return this.relationshipService.create(createRelationshipInput);
  }

  
  @Query(() => StixRelationship)
  async relationship(@Args('id') id: string): Promise<StixRelationship> {
    return this.relationshipService.findOne(id);
  }

  @Mutation(() => StixRelationship)
  async updateRelationship(
    @Args('id') id: string,
    @Args('updateRelationshipInput') updateRelationshipInput: UpdateRelationshipInput
  ): Promise<StixRelationship> {
    return this.relationshipService.update(id, updateRelationshipInput);
  }

  @Mutation(() => Boolean)
  async removeRelationship(@Args('id') id: string): Promise<boolean> {
    return this.relationshipService.remove(id);
  }





  // Search relationships with filters
  @Query(() => StixRelationship, { description: 'Search relationships with filters' })
  async searchRelationships(
    @Args('filters', { type: () => SearchRelationshipInput, nullable: true }) filters?: Partial<SearchRelationshipInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number
  ): Promise<any> {
    return this.relationshipService.searchWithFilters(filters, page, pageSize);
  }

  //  Find relationships directly linked to an object
  @Query(() => [StixRelationship], { description: 'Find related objects for a given STIX ID' })
  async relatedObjects(@Args('objectId', { type: () => String }) objectId: string): Promise<StixRelationship[]> {
    return this.relationshipService.findRelatedObjects(objectId);
  }

  //  Find all expanded related objects
  @Query(() => [StixRelationship], { description: 'Find all expanded related objects' })
  async expandedRelatedObjects(@Args('objectId', { type: () => String }) objectId: string): Promise<any[]> {
    return this.relationshipService.findExpandedRelatedObjects(objectId);
  }
}