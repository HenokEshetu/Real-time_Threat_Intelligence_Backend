import { Resolver, Query, Args } from '@nestjs/graphql';
import { StixObject } from './stix-objects.union';
import { RelationshipService } from './relationships/relationship.service';

@Resolver()
export class RelationshipResolver {
  constructor(private readonly relationshipService: RelationshipService) {}

  @Query(() => [StixObject], { name: 'getObjectsByIDs' })
  async getObjectsByIDs(
    @Args('ids', { type: () => [String] }) ids: string[],
  ): Promise<(typeof StixObject)[]> {
    return this.relationshipService.getObjectsByIds(ids);
  }
}
