import { Resolver, Int,InputType, Query, Mutation, Args } from '@nestjs/graphql';
import { ArtifactService } from './artifact.service';
import { Artifact } from './artifact.entity';
import { CreateArtifactInput, UpdateArtifactInput } from './artifact.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchArtifactInput extends PartialType(CreateArtifactInput) {}

@Resolver(() => Artifact)
export class ArtifactResolver {
  constructor(private readonly artifactService: ArtifactService) {}

  @Mutation(() => Artifact)
  async createArtifact(
    @Args('createArtifactInput') createArtifactInput: CreateArtifactInput,
  ): Promise<Artifact> {
    return this.artifactService.create(createArtifactInput);
  }

  @Query(() => [Artifact])
  async artifacts(
    @Args('searchParams', { type: () => SearchArtifactInput, nullable: true }) searchParams?:SearchArtifactInput,
    @Args('page', { type: () => Int, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize?: number
  ): Promise<Artifact[]> {
    const from = (page - 1) * pageSize;
    const result = await this.artifactService.searchWithFilters(searchParams || {}, from, pageSize);
    return result.results;
  }

  @Query(() => Artifact)
  async artifact(@Args('id') id: string): Promise<Artifact> {
    return this.artifactService.findOne(id);
  }

  @Mutation(() => Artifact)
  async updateArtifact(
    @Args('id') id: string,
    @Args('updateArtifactInput') updateArtifactInput: UpdateArtifactInput,
  ): Promise<Artifact> {
    return this.artifactService.update(id, updateArtifactInput);
  }

  @Mutation(() => Boolean)
  async removeArtifact(@Args('id') id: string): Promise<boolean> {
    return this.artifactService.remove(id);
  }
}