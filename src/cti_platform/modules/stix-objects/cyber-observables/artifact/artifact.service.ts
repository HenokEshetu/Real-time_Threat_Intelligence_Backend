import {
  Injectable,
  NotFoundException,
  InternalServerErrorException,
  OnModuleInit,
} from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateArtifactInput, UpdateArtifactInput } from './artifact.input';
import { SearchArtifactInput } from './artifact.resolver';
import { v4 as uuidv4 } from 'uuid';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { Artifact } from './artifact.entity';
import { Hashes } from '../../../../core/types/common-data-types'; // Import Hashes directly

@Injectable()
export class ArtifactService implements OnModuleInit {
  private readonly index = 'artifacts';
  private readonly openSearchClient: Client;

  constructor() {
    const clientOptions: ClientOptions = {
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
      ssl:
        process.env.OPENSEARCH_SSL === 'true'
          ? { rejectUnauthorized: false }
          : undefined,
      auth:
        process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD
          ? {
              username: process.env.OPENSEARCH_USERNAME,
              password: process.env.OPENSEARCH_PASSWORD,
            }
          : undefined,
    };
    this.openSearchClient = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }
  async create(createArtifactInput: CreateArtifactInput): Promise<Artifact> {
    this.validateArtifact(createArtifactInput);

    const timestamp = new Date().toISOString();
    const id = createArtifactInput.id;
    const artifact: Artifact = {
      id,
      type: 'artifact' as const,
      spec_version: '2.1',
      created: timestamp,
      modified: timestamp,
      ...createArtifactInput,
      hashes: this.convertHashesInputToHashes(createArtifactInput.hashes),
      ...(createArtifactInput.enrichment
        ? { enrichment: createArtifactInput.enrichment }
        : {}), // Optional enrichment
    };

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: artifact,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to create artifact');
      }
      return artifact;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create artifact',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchArtifactInput = {},
    from: number = 0,
    size: number = 10,
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Artifact[];
  }> {
    try {
      const timestamp = new Date().toISOString(); // Define timestamp here
      const queryBuilder: { query: any; sort?: any[] } = {
        query: {
          bool: {
            must: [],
            filter: [],
          },
        },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(searchParams)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'mime_type':
          case 'url':
            queryBuilder.query.bool.must.push({
              wildcard: { [key]: `*${value.toLowerCase()}*` },
            });
            break;
          case 'created':
          case 'modified':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: {
                  [key]: { gte: value.toISOString(), lte: value.toISOString() },
                },
              });
            }
            break;
          case 'hashes':
            if (typeof value === 'object' && !Array.isArray(value)) {
              Object.entries(value).forEach(([algo, hash]) => {
                queryBuilder.query.bool.filter.push({
                  term: { [`hashes.${algo}`]: hash },
                });
              });
            }
            break;
          default:
            queryBuilder.query.bool.must.push({ match: { [key]: value } });
        }
      }

      if (
        !queryBuilder.query.bool.must.length &&
        !queryBuilder.query.bool.filter.length
      ) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.openSearchClient.search({
        index: this.index,
        from,
        size,
        body: queryBuilder,
      });

      const total =
        typeof response.body.hits.total === 'object'
          ? response.body.hits.total.value
          : response.body.hits.total;

      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results: response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          type: 'artifact' as const,
          spec_version: '2.1',
          created: hit._source.created || timestamp,
          modified: hit._source.modified || timestamp,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search artifacts',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(
    id: string,
    mockArtifacts: Record<string, any>[],
  ): Promise<Artifact> {
    try {
      // const response = await this.openSearchClient.get({
      //   index: this.index,
      //   id,
      // });

      // return {
      //   ...response.body._source,
      //   id: response.body._id,
      //   type: 'artifact' as const,
      //   spec_version: '2.1',
      //   created: response.body._source.created || new Date().toISOString(),
      //   modified: response.body._source.modified || new Date().toISOString(),
      // };

      const response = mockArtifacts.find((artifact) => artifact.id === id);

      return response as Artifact;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Artifact with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch artifact',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(
    id: string,
    updateArtifactInput: UpdateArtifactInput,
  ): Promise<Artifact> {
    this.validateArtifact(updateArtifactInput);

    try {
      const existing = await this.findOne(id, null);
      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: {
          doc: {
            ...updateArtifactInput,
            modified: new Date().toISOString(),
            hashes: this.convertHashesInputToHashes(updateArtifactInput.hashes),
          },
        },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update artifact');
      }
      return {
        ...existing,
        ...updateArtifactInput,
        modified: new Date().toISOString(),
        type: 'artifact' as const,
        hashes: this.convertHashesInputToHashes(updateArtifactInput.hashes),
      };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update artifact',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) return false;
      throw new InternalServerErrorException({
        message: 'Failed to delete artifact',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateArtifact(
    input: CreateArtifactInput | UpdateArtifactInput,
  ): void {
    const hasUrl = 'url' in input && input.url !== undefined;
    const hasPayload =
      'payload_bin' in input && input.payload_bin !== undefined;

    if (hasUrl && hasPayload) {
      throw new StixValidationError(
        'An artifact cannot have both url and payload_bin properties',
      );
    }
    if (!hasUrl && !hasPayload && !('id' in input)) {
      throw new StixValidationError(
        'An artifact must have either url or payload_bin property',
      );
    }

    if (hasUrl && !this.isValidUrl(input.url)) {
      throw new StixValidationError('Invalid URL format');
    }
    if (input.mime_type && !this.isValidMimeType(input.mime_type)) {
      throw new StixValidationError('Invalid MIME type format');
    }
    if (input.hashes) {
      this.validateHashes(this.convertHashesInputToHashes(input.hashes));
    }
  }

  private isValidMimeType(mimeType: string): boolean {
    return /^[a-zA-Z0-9][a-zA-Z0-9-+.]*\/[a-zA-Z0-9][a-zA-Z0-9-+.]*$/.test(
      mimeType,
    );
  }

  private isValidUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      return ['http:', 'https:', 'file:'].includes(parsed.protocol);
    } catch {
      return false;
    }
  }

  private convertHashesInputToHashes(
    hashesInput?: any,
  ): Record<string, string> | undefined {
    if (!hashesInput || typeof hashesInput !== 'object') return undefined;
    const result: Record<string, string> = {};
    Object.entries(hashesInput).forEach(([algorithm, value]) => {
      if (typeof value === 'string') {
        result[algorithm] = value;
      }
    });
    return result;
  }

  private validateHashes(hashes: Record<string, string> | undefined): void {
    if (!hashes) return;
    const validHashAlgorithms = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'];
    for (const [algorithm, value] of Object.entries(hashes)) {
      if (!algorithm || !value) {
        throw new StixValidationError('Hash must have algorithm and value');
      }
      if (!validHashAlgorithms.includes(algorithm)) {
        throw new StixValidationError(
          `Invalid hash algorithm: ${algorithm}. Must be one of ${validHashAlgorithms.join(', ')}`,
        );
      }
      if (
        typeof value !== 'string' ||
        !this.isValidHashFormat(algorithm, value)
      ) {
        throw new StixValidationError(
          `Invalid ${algorithm} hash value: ${value}`,
        );
      }
    }
  }

  private isValidHashFormat(algorithm: string, hash: string): boolean {
    const hashPatterns: Record<string, RegExp> = {
      MD5: /^[a-fA-F0-9]{32}$/,
      'SHA-1': /^[a-fA-F0-9]{40}$/,
      'SHA-256': /^[a-fA-F0-9]{64}$/,
      'SHA-512': /^[a-fA-F0-9]{128}$/,
    };
    return hashPatterns[algorithm]?.test(hash) ?? false;
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchClient.indices.exists({
        index: this.index,
      });
      if (!exists.body) {
        await this.openSearchClient.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                mime_type: { type: 'keyword' },
                url: { type: 'text' },
                payload_bin: { type: 'binary' },
                hashes: { type: 'object' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize artifact index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}
