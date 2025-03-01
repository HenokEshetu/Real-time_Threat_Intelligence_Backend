import { Injectable, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateArtifactInput, UpdateArtifactInput } from './artifact.input';
import { v4 as uuidv4 } from 'uuid';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { InternalServerErrorException } from '@nestjs/common'
import { SearchArtifactInput } from './artifact.resolver';
@Injectable()
export class ArtifactService {
  private readonly index = 'artifacts';
  private openSearchClient: Client;

  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createArtifactInput: CreateArtifactInput): Promise<any> {
    this.validateArtifact(createArtifactInput);
    const id = `artifact--${uuidv4()}`;
    const artifact = { id, ...createArtifactInput };
    
    await this.openSearchClient.index({
      index: this.index,
      id,
      body: artifact,
    });
    return artifact;
  }

  async searchWithFilters(
    searchParams: SearchArtifactInput, 
    from: number = 0, 
    size: number = 10
  ): Promise<any> {
    try {
      // Construct OpenSearch query based on provided searchParams
      const mustQueries = [];
  
      for (const [key, value] of Object.entries(searchParams)) {
        if (value) {
          mustQueries.push({ match: { [key]: value } });
        }
      }
  
      const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };
  
      const { body } = await this.openSearchClient.search({
        index: this.index,
        body: {
          query,
        },
        from,
        size,
      });
  
      // Extract total number of hits
      const total = body.hits.total instanceof Object ? body.hits.total.value : body.hits.total;
  
      // Return paginated search results
      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results: body.hits.hits.map((hit) => hit._source),
      };
    } catch (error) {
      throw new InternalServerErrorException('Error fetching data from OpenSearch');
    }
  }
  
  

  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchClient.get({
        index: this.index,
        id,
      });
      return body._source;
    } catch (error) {
      throw new NotFoundException(`Artifact with ID ${id} not found`);
    }
  }

  async update(id: string, updateArtifactInput: UpdateArtifactInput): Promise<any> {
    this.validateArtifact(updateArtifactInput);
    await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updateArtifactInput },
    });
    return this.findOne(id);
  }

  async remove(id: string): Promise<boolean> {
    const { body } = await this.openSearchClient.delete({ index: this.index, id });
    return body.result === 'deleted';
  }

  private validateArtifact(input: CreateArtifactInput | UpdateArtifactInput): void {
    if (input.url && input.payload_bin) {
      throw new StixValidationError('An artifact cannot have both url and payload_bin properties');
    }
    if (!input.url && !input.payload_bin) {
      throw new StixValidationError('An artifact must have either url or payload_bin property');
    }
    if (input.mime_type && !this.isValidMimeType(input.mime_type)) {
      throw new StixValidationError('Invalid MIME type format');
    }
    if (input.url && !this.isValidUrl(input.url)) {
      throw new StixValidationError('Invalid URL format');
    }
    if (input.hashes) {
      this.validateHashes(input.hashes);
    }
  }

  private isValidMimeType(mimeType: string): boolean {
    return /^[a-zA-Z0-9]+\/[a-zA-Z0-9\-\+\.]+$/.test(mimeType);
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  private validateHashes(hashes: any): void {
    const validHashAlgorithms = ['MD5', 'SHA_1', 'SHA_256', 'SHA_512'];
    for (const [algorithm, hash] of Object.entries(hashes)) {
      if (!validHashAlgorithms.includes(algorithm)) {
        throw new StixValidationError(`Invalid hash algorithm: ${algorithm}`);
      }
      if (typeof hash !== 'string') {
        throw new StixValidationError(`Hash value must be a string: ${algorithm}`);
      }
      if (!this.isValidHashFormat(algorithm, hash)) {
        throw new StixValidationError(`Invalid ${algorithm} hash format`);
      }
    }
  }

  private isValidHashFormat(algorithm: string, hash: string): boolean {
    const hashPatterns: Record<string, RegExp> = {
      'MD5': /^[a-fA-F0-9]{32}$/,
      'SHA_1': /^[a-fA-F0-9]{40}$/,
      'SHA_256': /^[a-fA-F0-9]{64}$/,
      'SHA_512': /^[a-fA-F0-9]{128}$/,
    };
    return hashPatterns[algorithm]?.test(hash) ?? false;
  }
}
