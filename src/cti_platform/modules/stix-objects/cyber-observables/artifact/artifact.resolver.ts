import { Resolver, Int,InputType, Query, Mutation, Args, ObjectType, Field, Subscription } from '@nestjs/graphql';
import { ArtifactService } from './artifact.service';
import { Artifact } from './artifact.entity';
import { CreateArtifactInput, UpdateArtifactInput } from './artifact.input';

import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Inject } from '@nestjs/common';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';

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
  
  
  constructor(
        private readonly artifactService: ArtifactService,
        @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
      ) {}
    
      // Date conversion helper
      public convertDates(payload: any): Artifact {
        const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
        dateFields.forEach(field => {
          if (payload[field]) payload[field] = new Date(payload[field]);
        });
        return payload;
      }
    
      // Subscription Definitions
      @Subscription(() => Artifact, {
        name: 'artifactCreated',
        resolve: (payload) => payload,
      })
     artifactCreated() {
        return this.pubSub.asyncIterator('artifactCreated');
      }
    
      @Subscription(() => Artifact, {
        name: 'artifactUpdated',
        resolve: (payload) => payload,
      })
      artifactUpdated() {
        return this.pubSub.asyncIterator('artifactUpdated');
      }
    
      @Subscription(() => String, { name: 'artifactDeleted' })
      artifactDeleted() {
        return this.pubSub.asyncIterator('artifactDeleted');
      }
  

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