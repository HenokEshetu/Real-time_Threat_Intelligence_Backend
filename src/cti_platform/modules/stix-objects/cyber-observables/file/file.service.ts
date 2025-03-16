import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateFileInput, UpdateFileInput } from './file.input';
import { File } from './file.entity';
import { SearchFileInput } from './file.resolver';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';

@Injectable()
export class FileService implements OnModuleInit {
  private readonly index = 'files';
  private readonly openSearchClient: Client;

  constructor() {
    const clientOptions: ClientOptions = {
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
      ssl: process.env.OPENSEARCH_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      auth: process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD
        ? {
            username: process.env.OPENSEARCH_USERNAME,
            password: process.env.OPENSEARCH_PASSWORD,
          }
        : undefined,
    };
    this.openSearchClient = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();}

  async create(createFileInput: CreateFileInput): Promise<File> {
    const id = `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const now = new Date().toISOString();

    const doc: File = {
      id,
      type: 'file' as const,
      spec_version: '2.1',
      created: now,
      modified: now,
      ...createFileInput,
    };

    // Validate and convert hashes if provided
    if (doc.hashes) {
      const convertedHashes = this.convertHashesInputToHashes(doc.hashes);
      this.validateHashes(convertedHashes);
      // Assign record directly instead of converting to an array
      doc.hashes = convertedHashes;
    }

    try {
      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }
      return doc;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create file',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateFileInput: UpdateFileInput): Promise<File> {
    try {
      const existing = await this.findOne(id);
      if (!existing) {
        throw new NotFoundException(`File with ID ${id} not found`);
      }

      // Validate and convert hashes if provided in update
      if (updateFileInput.hashes) {
        const convertedHashes = this.convertHashesInputToHashes(updateFileInput.hashes);
        this.validateHashes(convertedHashes);
        // Assign record directly
        updateFileInput.hashes = convertedHashes;
      }

      const updatedDoc: Partial<File> = {
        ...updateFileInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update document');
      }

      return { ...existing, ...updatedDoc };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update file',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    searchParams: SearchFileInput = {},
    from: number = 0,
    size: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: File[];
  }> {
    try {
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
          case 'name':
          case 'mime_type':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'created':
          case 'modified':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
              });
            }
            break;
          case 'hashes':
            if (typeof value === 'object' && !Array.isArray(value)) {
              Object.entries(value).forEach(([hashType, hashValue]) => {
                queryBuilder.query.bool.filter.push({
                  term: { [`hashes.${hashType}`]: hashValue },
                });
              });
            }
            break;
          default:
            queryBuilder.query.bool.must.push({
              term: { [key]: value },
            });
        }
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.openSearchClient.search({
        index: this.index,
        from,
        size,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'object'
        ? response.body.hits.total.value
        : response.body.hits.total;

      return {
        page: Math.floor(from / size) + 1,
        pageSize: size,
        total,
        totalPages: Math.ceil(total / size),
        results: response.body.hits.hits.map((hit) => ({
          id: hit._id,
          type: 'file' as const,
          spec_version: '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search files',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<File> {
    try {
      const response = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        id,
        type: 'file' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        ...source,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`File with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch file',
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
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete file',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByHash(hashValue: string): Promise<File[]> {
    try {
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: {
            bool: {
              should: [
                { match: { 'hashes.SHA-256': hashValue } },
                { match: { 'hashes.MD5': hashValue } },
                { match: { 'hashes.SHA-1': hashValue } },
              ],
              minimum_should_match: 1,
            },
          },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'file' as const,
        spec_version: hit._source.spec_version || '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        hashes: hit._source.hashes,
        ...hit._source,
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to find files by hash',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchClient.indices.exists({ index: this.index });
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
                name: { type: 'text' },
                mime_type: { type: 'keyword' },
                hashes: { type: 'object' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize files index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  // Hash validation utilities
  private convertHashesInputToHashes(hashesInput?: any): Record<string, string> | undefined {
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
    const validHashAlgorithms = ['MD5', 'SHA_1', 'SHA_256', 'SHA_512'];
    for (const [algorithm, value] of Object.entries(hashes)) {
      if (!algorithm || !value) {
        throw new StixValidationError('Hash must have algorithm and value');
      }
      if (!validHashAlgorithms.includes(algorithm)) {
        throw new StixValidationError(`Invalid hash algorithm: ${algorithm}. Must be one of ${validHashAlgorithms.join(', ')}`);
      }
      if (typeof value !== 'string' || !this.isValidHashFormat(algorithm, value)) {
        throw new StixValidationError(`Invalid ${algorithm} hash value: ${value}`);
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