import {
  Resolver,
  Int,
  InputType,
  Query,
  Mutation,
  Args,
  ObjectType,
  Field,
  PartialType,
} from '@nestjs/graphql';
import { Artifact } from './artifact.entity';
import { ArtifactService } from './artifact.service';
import { CreateArtifactInput, UpdateArtifactInput } from './artifact.input';

@InputType()
export class SearchArtifactInput extends PartialType(CreateArtifactInput) {}

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
    const mockArtifacts: Artifact[] = [
      {
        id: 'file--7285f64e-5bb9-4423-9492-4ad5fc7c3f46',
        type: 'file',
        spec_version: '2.1',
        created: '2025-04-14T18:18:05.769Z',
        modified: '2025-04-14T18:18:05.769Z',
        mime_type: 'application/pdf',
        url: 'https://example.com/sample-file.pdf',
        payload_bin: 'c2FtcGxlLWRhdGE=',
        hashes: {
          MD5: 'd41d8cd98f00b204e9800998ecf8427e',
          'SHA-1': '2ef7bde608ce5404e97d5f042f95f89f1c232871',
          'SHA-256': '6d4b46c4f45a4926c36a3c7d6ff9b8ad276745b424af8d11f024174db2b01c29',
          'SHA-512': 'd2d2d2d8d9d2e1d2d7d3f7e1f4f5e6f7d2b8e9d0d1d6d4d0d7d9e1b2b7c8d6f8',
        },
        enrichment: {},
        confidence: 90,
        created_by_ref: 'identity--7fc7a09e-104a-46ea-9ccf-a835bf25b72c',
        revoked: false,
        labels: ['AlienVault-OTX', 'alienvault-otx'],
        external_references: [],
        extensions: {},
        lang: 'en',
        decryption_key: null,
        encryption_algorithm: null,
        object_marking_refs: [],
      },
      {
        id: 'file--e234f64e-2b28-484a-8f3a-df2d6ab38c2e',
        type: 'file',
        spec_version: '2.1',
        created: '2025-04-14T18:22:10.769Z',
        modified: '2025-04-14T18:22:10.769Z',
        mime_type: 'application/zip',
        url: 'https://example.com/sample-archive.zip',
        payload_bin: 'c2FtcGxlLWRhdGE=',
        hashes: {
          MD5: 'a47e6d73f8eebf7f17cf1e0de8b739fc',
          'SHA-1': '8e9d1a28399d8630d2f1a2bca14d169b2686dbd5',
          'SHA-256': '8b6e9d1a1b3f2fa6848fe5473b0416076b3b92d0edff4d2f779107f9ef4d720d',
          'SHA-512': 'e4e563ee9f759263fe3efc09b69d33d85d5d074dba5b616ea5867261d4f8122e',
        },
        enrichment: {},
        confidence: 85,
        created_by_ref: 'identity--f56b8f61-244b-4b0e-9533-b2d3f5bbbd01',
        revoked: false,
        labels: ['AlienVault-OTX'],
        external_references: [],
        extensions: {},
        lang: 'en',
        decryption_key: null,
        encryption_algorithm: null,
        object_marking_refs: [],
      },
      // Add more results here if needed
    ];
  
    // Ensure you're slicing the data based on `from` and `size` to return the correct page
    const paginatedResults = mockArtifacts.slice(from, from + size);
  
    return {
      page: 1,
      pageSize: size,
      total: mockArtifacts.length,
      totalPages: Math.ceil(mockArtifacts.length / size),
      results: paginatedResults,
    };
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
