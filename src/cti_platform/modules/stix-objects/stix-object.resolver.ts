import { Resolver, Query, Args } from '@nestjs/graphql';
import { StixObject } from './stix-objects.union';
import { RelationshipService } from './relationships/relationship.service';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@Resolver()
export class RelationshipResolver {
  constructor(private readonly relationshipService: RelationshipService) {}

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => [StixObject], { name: 'getObjectsByIDs' })
  async getObjectsByIDs(
    @Args('ids', { type: () => [String] }) ids: string[],
  ): Promise<(typeof StixObject)[]> {
    return this.relationshipService.getObjectsByIds(ids);
  }
}
