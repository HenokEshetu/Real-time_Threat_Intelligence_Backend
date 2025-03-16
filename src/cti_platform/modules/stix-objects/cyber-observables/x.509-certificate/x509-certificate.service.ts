import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client } from '@opensearch-project/opensearch';
import { CreateX509CertificateInput, UpdateX509CertificateInput } from './x509-certificate.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { SearchX509CertificateInput } from './x509-certificate.resolver';
@Injectable()
export class X509CertificateService {
  private readonly opensearchClient: Client;
  private readonly index = 'x509-certificates'; // OpenSearch index name

  constructor() {
    this.opensearchClient = new Client({
      node: 'http://localhost:9200',
     
    });
  }

  /**
   * Create a new X.509 Certificate in OpenSearch
   */
  async create(createX509CertificateInput: CreateX509CertificateInput): Promise<any> {
    this.validateX509Certificate(createX509CertificateInput);

    const x509Certificate = {
      ...createX509CertificateInput,
      id: `x509-certificate--${uuidv4()}`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    try {
      const response = await this.opensearchClient.index({
        index: this.index,
        id: x509Certificate.id,
        body: x509Certificate,
      });

      return response.body;
    } catch (error) {
      throw new InternalServerErrorException('Error creating X.509 certificate in OpenSearch');
    }
  }

  /**
   * Find all certificates with optional filters and pagination
   */
  async searchWithFilters(
    filters?: SearchX509CertificateInput,
    from: number = 0,
    size: number = 10
  ): Promise<any[]> {
    const mustQueries = [];

    // Apply filters dynamically
    for (const [key, value] of Object.entries(filters || {})) {
      if (value !== undefined) {
        if (typeof value === 'string') {
          mustQueries.push({
            match: {
              [key]: {
                query: value,
                fuzziness: 'AUTO', // Fuzzy matching for flexible search
              },
            },
          });
        } else {
          mustQueries.push({
            match: {
              [key]: value,
            },
          });
        }
      }
    }

    const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };

    try {
      const response = await this.opensearchClient.search({
        index: this.index,
        body: { query, from, size },
      });

      return response.body.hits.hits.map((hit) => hit._source);
    } catch (error) {
      throw new InternalServerErrorException('Error fetching X.509 certificates from OpenSearch');
    }
  }

  /**
   * Find a single X.509 certificate by ID
   */
  async findOne(id: string): Promise<any> {
    try {
      const response = await this.opensearchClient.get({ index: this.index, id });
      return response.body._source;
    } catch (error) {
      throw new NotFoundException('X.509 certificate not found');
    }
  }

  /**
   * Update an X.509 certificate in OpenSearch
   */
  async update(id: string, updateX509CertificateInput: UpdateX509CertificateInput): Promise<any> {
    this.validateX509Certificate(updateX509CertificateInput);

    try {
      const response = await this.opensearchClient.update({
        index: this.index,
        id,
        body: {
          doc: { ...updateX509CertificateInput, updated_at: new Date().toISOString() },
          doc_as_upsert: true, // Create if doesn't exist
        },
      });

      return response.body;
    } catch (error) {
      throw new InternalServerErrorException('Error updating X.509 certificate in OpenSearch');
    }
  }

  /**
   * Remove an X.509 certificate from OpenSearch
   */
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.opensearchClient.delete({ index: this.index, id });
      return response.body.result === 'deleted';
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate X.509 Certificate structure
   */
  private validateX509Certificate(input: CreateX509CertificateInput | UpdateX509CertificateInput): void {
    if (input.validity_not_before && input.validity_not_after) {
      if (input.validity_not_before > input.validity_not_after) {
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

  /**
   * Check if X.509 version is valid
   */
  private isValidVersion(version: string): boolean {
    return ['1', '2', '3'].includes(version);
  }

  /**
   * Check if serial number is valid (hexadecimal format)
   */
  private isValidSerialNumber(serialNumber: string): boolean {
    return /^[0-9a-fA-F]+$/.test(serialNumber);
  }

  /**
   * Validate cryptographic hashes
   */
  private validateHashes(hashes: any): void {
    const validHashAlgorithms = ['MD5', 'SHA_1', 'SHA_256', 'SHA_512'];

    for (const [algorithm, hash] of Object.entries(hashes)) {
      if (!validHashAlgorithms.includes(algorithm)) {
        throw new StixValidationError(`Invalid hash algorithm: ${algorithm}`);
      }

      if (typeof hash !== 'string') {
        throw new StixValidationError(`Hash value must be a string: ${algorithm}`);
      }

      switch (algorithm) {
        case 'MD5':
          if (!/^[a-fA-F0-9]{32}$/.test(hash)) {
            throw new StixValidationError(`Invalid MD5 hash format`);
          }
          break;
        case 'SHA_1':
          if (!/^[a-fA-F0-9]{40}$/.test(hash)) {
            throw new StixValidationError(`Invalid SHA-1 hash format`);
          }
          break;
        case 'SHA_256':
          if (!/^[a-fA-F0-9]{64}$/.test(hash)) {
            throw new StixValidationError(`Invalid SHA-256 hash format`);
          }
          break;
        case 'SHA_512':
          if (!/^[a-fA-F0-9]{128}$/.test(hash)) {
            throw new StixValidationError(`Invalid SHA-512 hash format`);
          }
          break;
      }
    }
  }
}
