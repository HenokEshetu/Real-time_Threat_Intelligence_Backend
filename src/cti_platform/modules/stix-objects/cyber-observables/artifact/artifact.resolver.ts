import {
  Resolver,
  Int,
  InputType,
  Query,
  Mutation,
  Args,
  ObjectType,
  Field,
} from '@nestjs/graphql';
import { ArtifactService } from './artifact.service';
import { Artifact } from './artifact.entity';
import { CreateArtifactInput, UpdateArtifactInput } from './artifact.input';

import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';
@InputType()
export class SearchArtifactInput extends PartialType(CreateArtifactInput) {}

// Define the SearchResult type for paginated responses
@ObjectType()
export class ArtifactSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [Artifact])
  results: Artifact[];
}

@Resolver(() => Artifact)
export class ArtifactResolver extends BaseStixResolver(Artifact) {
  public typeName = 'artifact';

  constructor(private readonly artifactService: ArtifactService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => Artifact)
  async createArtifact(
    @Args('input') createArtifactInput: CreateArtifactInput,
  ): Promise<Artifact> {
    return this.artifactService.create(createArtifactInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => ArtifactSearchResult)
  async searchArtifacts(
    @Args('filters', { type: () => SearchArtifactInput, nullable: true })
    filters: SearchArtifactInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<ArtifactSearchResult> {
    return this.artifactService.searchWithFilters(filters, from, size);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => Artifact, { nullable: true })
  async artifactByID(@Args('id') id: string): Promise<Artifact> {
    return this.artifactService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => Artifact)
  async updateArtifact(
    @Args('id') id: string,
    @Args('input') updateArtifactInput: UpdateArtifactInput,
  ): Promise<Artifact> {
    return this.artifactService.update(id, updateArtifactInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteArtifact(@Args('id') id: string): Promise<boolean> {
    return this.artifactService.remove(id);
  }
}
