import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateFileInput, UpdateFileInput } from './file.input';
import { File } from './file.entity';
import { SearchFileInput } from './file.resolver';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@Injectable()
export class FileService extends BaseStixService<File> implements OnModuleInit {
  protected typeName = 'file';
  private readonly index = 'files';
  private readonly logger = console; 

  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createFileInput: CreateFileInput): Promise<File> {
    const now = new Date().toISOString();
  
    // Sanitize input and include supported properties
    const doc: File = {
      id: createFileInput.id,
      type: 'file',
      spec_version: '2.1',
      created: now,
      modified: now,
      name: createFileInput.name,
      mime_type: createFileInput.mime_type,
      hashes: createFileInput.hashes,
      extensions: createFileInput.extensions,
      labels: createFileInput.labels,
      external_references: createFileInput.external_references,
      object_marking_refs: createFileInput.object_marking_refs,
    };
  
    // Validate and convert hashes if provided
    if (doc.hashes) {
      const convertedHashes = this.convertHashesInputToHashes(doc.hashes);
      try {
        this.validateHashes(convertedHashes);
        doc.hashes = convertedHashes;
      } catch (error) {
        throw new InternalServerErrorException({
          message: 'Failed to validate file hashes',
          details: error.message,
          inputHashes: doc.hashes,
        });
      }
    }
  
  
    try {
      this.logger?.log(`Indexing file document`, { id: doc.id, hashes: doc.hashes, extensions: doc.extensions });
  
      // Check if document already exists
      const exists = await this.openSearchService.exists({
        index: this.index,
        id: doc.id,
      });
  
      if (exists.body) {
        this.logger?.warn(`Document already exists`, { id: doc.id });
        
        const existingDoc = await this.findOne(doc.id);
        return existingDoc;
        
      }
  
      const response = await this.openSearchService.index({
        index: this.index,
        id: doc.id,
        body: doc,
        refresh: 'wait_for',
      });
  
      if (response.body.result === 'created') {
        this.logger?.log(`Successfully created file document`, { id: doc.id });
        await this.publishCreated(doc);
        return doc;
      } else if (response.body.result === 'updated') {
        this.logger?.warn(`Document was updated instead of created`, { id: doc.id });
        // Retrieve the updated document
        const updatedDoc = await this.findOne(doc.id);
        await this.publishCreated(updatedDoc);
        return updatedDoc;
      } else {
        throw new Error(`Unexpected index result: ${response.body.result}`);
      }
    } catch (error) {
      const errorDetails = JSON.stringify(error?.meta?.body?.error || error?.meta || error?.message || 'Unknown error');
      this.logger?.error(`Failed to index file`, {
        id: doc.id,
        error: errorDetails,
        input: createFileInput,
        errorCode: error?.meta?.statusCode,
      });
      throw new InternalServerErrorException({
        message: `Failed to create file with ID ${doc.id}`,
        details: errorDetails,
        input: createFileInput,
        errorCode: error?.meta?.statusCode,
      });
    }
  }

  async update(id: string, updateFileInput: UpdateFileInput): Promise<File> {
    try {
      const existing = await this.findOne(id);
      if (!existing) {
        throw new NotFoundException(`File with ID ${id} not found`);
      }

      if (updateFileInput.hashes) {
        const convertedHashes = this.convertHashesInputToHashes(updateFileInput.hashes);
        try {
          this.validateHashes(convertedHashes);
          updateFileInput.hashes = convertedHashes;
        } catch (error) {
          throw new InternalServerErrorException({
            message: 'Failed to validate file hashes',
            details: error.message,
            inputHashes: updateFileInput.hashes,
          });
        }
      }

      const updatedDoc: Partial<File> = {
        ...updateFileInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error(`Failed to update document: ${response.body.result}`);
      }

      await this.publishUpdated({ ...existing, ...updatedDoc });
      return { ...existing, ...updatedDoc };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: `Failed to update file with ID ${id}`,
        details: error.meta?.body?.error || error.message,
        input: updateFileInput,
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
        sort: [{ modified: { order: 'desc' } }],
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

      const response = await this.openSearchService.search({
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
          ...hit._source,
          id: hit._id,
          type: 'file',
          spec_version: '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
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
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id,
        type: 'file',
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`File with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: `Failed to fetch file with ID ${id}`,
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
      });
      await this.publishDeleted(id);
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: `Failed to delete file with ID ${id}`,
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findByHash(hashValue: string): Promise<File[]> {
    try {
      const response = await this.openSearchService.search({
        index: this.index,
        body: {
          query: {
            bool: {
              should: [
                { match: { 'hashes.SHA-256': hashValue } },
                { match: { 'hashes.MD5': hashValue } },
                { match: { 'hashes.SHA-1': hashValue } },
                { match: { 'hashes.SHA-512': hashValue } },
              ],
              minimum_should_match: 1,
            },
          },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
        type: 'file',
        spec_version: hit._source.spec_version || '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        hashes: hit._source.hashes,
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: `Failed to find files by hash ${hashValue}`,
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchService.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchService.indices.create({
          index: this.index,
          body: {
            mappings: {
              dynamic: 'true',
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                name: { type: 'text' },
                mime_type: { type: 'keyword' },
                hashes: { type: 'object' },
                labels: { type: 'keyword' },
                external_references: {
                  type: 'nested',
                  properties: {
                    source_name: { type: 'keyword' },
                    external_id: { type: 'keyword' },
                    url: { type: 'keyword' },
                  },
                },
                object_marking_refs: { type: 'keyword' },
                extensions: {
                  type: 'object',
                  dynamic: 'true', // Allow dynamic mapping for any extension key
                },
              },
            },
          },
        });
        this.logger?.log(`Created ${this.index} index`);
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize files index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private convertHashesInputToHashes(hashesInput?: any): Record<string, string> | undefined {
    if (!hashesInput || typeof hashesInput !== 'object') return undefined;
    const result: Record<string, string> = {};
    Object.entries(hashesInput).forEach(([algorithm, value]) => {
      if (typeof value === 'string') {
        const normalizedAlgorithm = this.normalizeHashAlgorithm(algorithm);
        result[normalizedAlgorithm] = value;
      }
    });
    return Object.keys(result).length > 0 ? result : undefined;
  }

  private validateHashes(hashes: Record<string, string> | undefined): void {
    if (!hashes) return;
    const validHashAlgorithms = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'];
    for (const [algorithm, value] of Object.entries(hashes)) {
      if (!algorithm || !value) {
        throw new StixValidationError('Hash must have algorithm and value');
      }
      const normalizedAlgorithm = this.normalizeHashAlgorithm(algorithm);
      if (!validHashAlgorithms.includes(normalizedAlgorithm)) {
        throw new StixValidationError(
          `Invalid hash algorithm: ${algorithm}. Must be one of ${validHashAlgorithms.join(', ')}`
        );
      }
      if (typeof value !== 'string' || !this.isValidHashFormat(normalizedAlgorithm, value)) {
        const foundAlgo = validHashAlgorithms.find((algo) => this.isValidHashFormat(algo, value));
        if (foundAlgo && foundAlgo !== normalizedAlgorithm) {
          delete hashes[algorithm];
          hashes[foundAlgo] = value;
        } else {
          throw new StixValidationError(`Invalid ${normalizedAlgorithm} hash value: ${value}`);
        }
      }
    }
  }

  private normalizeHashAlgorithm(algorithm: string): string {
    const algorithmMap: Record<string, string> = {
      md5: 'MD5',
      sha1: 'SHA-1',
      'sha-1': 'SHA-1',
      sha256: 'SHA-256',
      'sha-256': 'SHA-256',
      sha512: 'SHA-512',
      'sha-512': 'SHA-512',
    };
    return algorithmMap[algorithm.toLowerCase()] || algorithm;
  }

  private isValidHashFormat(algorithm: string, hash: string): boolean {
    const hashPatterns: Record<string, RegExp> = {
      'MD5': /^[a-fA-F0-9]{32}$/,
      'SHA-1': /^[a-fA-F0-9]{40}$/,
      'SHA-256': /^[a-fA-F0-9]{64}$/,
      'SHA-512': /^[a-fA-F0-9]{128}$/,
    };
    return hashPatterns[algorithm]?.test(hash) ?? false;
  }
}