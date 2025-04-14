import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateX509CertificateInput, UpdateX509CertificateInput } from './x509-certificate.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { SearchX509CertificateInput } from './x509-certificate.resolver';
import { X509Certificate } from './x509-certificate.entity';

@Injectable()
export class X509CertificateService implements OnModuleInit{
  private readonly opensearchClient: Client;
  private readonly index = 'x509-certificates';

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
    this.opensearchClient = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();}

  async create(createX509CertificateInput: CreateX509CertificateInput): Promise<X509Certificate> {
    this.validateX509Certificate(createX509CertificateInput);

    const x509Certificate: X509Certificate = {
      id: `x509-certificate--${uuidv4()}`,
      type: 'x509-certificate' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createX509CertificateInput,
      ...(createX509CertificateInput.enrichment ? { enrichment: createX509CertificateInput.enrichment } : {}),
    };

    try {
      const response = await this.opensearchClient.index({
        index: this.index,
        id: x509Certificate.id,
        body: x509Certificate,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index X.509 certificate');
      }
      return x509Certificate;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create X.509 certificate',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchX509CertificateInput = {},
    from: number = 0,
    size: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: X509Certificate[];
  }> {
    try {
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(filters)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'issuer':
          case 'subject':
          case 'serial_number':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, fuzziness: 'AUTO' } },
            });
            break;
          case 'created':
          case 'modified':
          case 'validity_not_before':
          case 'validity_not_after':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
              });
            }
            break;
          case 'version':
          case 'hashes':
            queryBuilder.query.bool.filter.push({
              term: { [key]: value },
            });
            break;
          default:
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, fuzziness: 'AUTO' } },
            });
        }
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length) {
        queryBuilder.query = { match_all: {} };
      }

      const response = await this.opensearchClient.search({
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
          type: 'x509-certificate' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search X.509 certificates',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<X509Certificate> {
    try {
      const response = await this.opensearchClient.get({ index: this.index, id });
      const source = response.body._source;
      return {
        id: response.body._id,
        type: 'x509-certificate' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        ...source,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`X.509 certificate with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch X.509 certificate',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateX509CertificateInput: UpdateX509CertificateInput): Promise<X509Certificate> {
    this.validateX509Certificate(updateX509CertificateInput);

    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<X509Certificate> = {
        ...updateX509CertificateInput,
        modified: new Date().toISOString(),
      };

      const response = await this.opensearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update X.509 certificate');
      }

      return { ...existing, ...updatedDoc };
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update X.509 certificate',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.opensearchClient.delete({ index: this.index, id });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete X.509 certificate',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateX509Certificate(input: CreateX509CertificateInput | UpdateX509CertificateInput): void {
    if (input.validity_not_before && input.validity_not_after) {
      const before = new Date(input.validity_not_before);
      const after = new Date(input.validity_not_after);
      if (before > after) {
        throw new StixValidationError('validity_not_before must be earlier than validity_not_after');
      }
    }

    if (input.version && !this.isValidVersion(input.version)) {
      throw new StixValidationError('Invalid X.509 version format');
    }

    if (input.serial_number && !this.isValidSerialNumber(input.serial_number)) {
      throw new StixValidationError('Invalid serial number format');
    }

    if (input.hashes) {
      this.validateHashes(input.hashes);
    }
  }

  private isValidVersion(version: string): boolean {
    return ['1', '2', '3'].includes(version);
  }

  private isValidSerialNumber(serialNumber: string): boolean {
    return /^[0-9a-fA-F]+$/.test(serialNumber);
  }

  private validateHashes(hashes: any): void {
    const validHashAlgorithms = ['MD5', 'SHA-1', 'SHA-256', 'SHA-512'];
    for (const [algorithm, hash] of Object.entries(hashes)) {
      const algo = algorithm.toUpperCase(); // normalize algorithm name
      if (!validHashAlgorithms.includes(algo)) {
        throw new StixValidationError(`Invalid hash algorithm: ${algorithm}`);
      }
      if (typeof hash !== 'string') {
        throw new StixValidationError(`Hash value must be a string: ${algorithm}`);
      }
      switch (algo) {
        case 'MD5':
          if (!/^[a-f0-9]{32}$/i.test(hash)) {
            throw new StixValidationError(`Invalid MD5 hash format`);
          }
          break;
        case 'SHA-1':
          if (!/^[a-f0-9]{40}$/i.test(hash)) {
            throw new StixValidationError(`Invalid SHA-1 hash format`);
          }
          break;
        case 'SHA-256':
          if (!/^[a-f0-9]{64}$/i.test(hash)) {
            throw new StixValidationError(`Invalid SHA-256 hash format`);
          }
          break;
        case 'SHA-512':
          if (!/^[a-f0-9]{128}$/i.test(hash)) {
            throw new StixValidationError(`Invalid SHA-512 hash format`);
          }
          break;
      }
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.opensearchClient.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.opensearchClient.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                issuer: { type: 'text' },
                subject: { type: 'text' },
                serial_number: { type: 'keyword' },
                version: { type: 'keyword' },
                validity_not_before: { type: 'date' },
                validity_not_after: { type: 'date' },
                hashes: { type: 'object' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize x509-certificates index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}