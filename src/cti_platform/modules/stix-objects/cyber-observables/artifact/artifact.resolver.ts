import { Resolver, Int,InputType, Query, Mutation, Args, ObjectType, Field } from '@nestjs/graphql';
import { ArtifactService } from './artifact.service';
import { Artifact } from './artifact.entity';
import { CreateArtifactInput, UpdateArtifactInput } from './artifact.input';

import { PartialType } from '@nestjs/graphql';
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
export class ArtifactResolver {
  constructor(private readonly artifactService: ArtifactService) {}

  @Mutation(() => Artifact)
  async createArtifact(
    @Args('input') createArtifactInput: CreateArtifactInput,
  ): Promise<Artifact> {
    return this.artifactService.create(createArtifactInput);
  }

  @Query(() => ArtifactSearchResult)
  async searchArtifacts(
    @Args('filters', { type: () => SearchArtifactInput, nullable: true }) filters: SearchArtifactInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<ArtifactSearchResult> {
    return this.artifactService.searchWithFilters(filters, from, size);
  }

  @Query(() => Artifact, { nullable: true })
  async artifactByID(@Args('id') id: string): Promise<Artifact> {
    return this.artifactService.findOne(id);
  }

  @Mutation(() => Artifact)
  async updateArtifact(
    @Args('id') id: string,
    @Args('input') updateArtifactInput: UpdateArtifactInput,
  ): Promise<Artifact> {
    return this.artifactService.update(id, updateArtifactInput);
  }

  @Mutation(() => Boolean)
  async deleteArtifact(@Args('id') id: string): Promise<boolean> {
    return this.artifactService.remove(id);
  }
}