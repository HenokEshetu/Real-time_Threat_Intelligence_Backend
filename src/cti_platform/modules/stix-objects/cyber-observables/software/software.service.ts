import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { CreateSoftwareInput, UpdateSoftwareInput } from './software.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { SearchSoftwareInput } from './software.resolver';
import { Software } from './software.entity';
import { BaseStixService } from '../../base-stix.service';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class SoftwareService extends BaseStixService<Software> implements OnModuleInit {
  protected typeName = ' software';
  private readonly index = 'software';
  private readonly logger = console; // Replace with a proper logger if needed


  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
  ) {
    super(pubSub);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createSoftwareInput: CreateSoftwareInput): Promise<Software> {
    this.validateSoftware(createSoftwareInput);



    const software: Software = {
      ...createSoftwareInput,
      id: createSoftwareInput.id,
      type: 'software' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),

    };

    // Check if document already exists
    const exists = await this.openSearchService.exists({
      index: this.index,
      id: software.id,
    });

    if (exists.body) {
      this.logger?.warn(`Document already exists`, { id: software.id });

      const existingDoc = await this.findOne(software.id);
      return existingDoc;

    }

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        body: software,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index software document');
      }



      await this.publishUpdated(software);
      return software;



    } catch (error) {
      throw new StixValidationError(`Failed to create software: ${error.meta?.body?.error || error.message}`);
    }
  }

  async findOne(id: string): Promise<Software> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'software' as const,
        name: source.name,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),

      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Software with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch software',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateSoftwareInput: UpdateSoftwareInput): Promise<Software> {
    this.validateSoftware(updateSoftwareInput);

    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<Software> = {
        ...updateSoftwareInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update software document');
      }

      const updatedSoftware: Software = {
        ...existing,
        spec_version: existing.spec_version || '2.1',
      };
      await this.publishUpdated(updatedSoftware);
      return updatedSoftware;

    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new StixValidationError(`Failed to update software: ${error.meta?.body?.error || error.message}`);
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
      });

      const success = response.body.result === 'deleted';
      if (success) {
        await this.publishDeleted(id);
      }
      return response.body.result === 'deleted';

    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete software',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateSoftware(input: CreateSoftwareInput | UpdateSoftwareInput): void {
    if ('name' in input && (!input.name || input.name.trim().length === 0)) {
      throw new StixValidationError('Software name cannot be empty');
    }

    if (input.cpe) {
      const cpeRegex = /^cpe:(?:2\.[23]|):[aho]:(?:[^:]+)(?::[^:]+){0,5}:(?:[^:]+|)(?::[^:]+|)$/;
      if (!cpeRegex.test(input.cpe)) {
        throw new StixValidationError('Invalid CPE format');
      }
    }

    if (input.swid) {
      input.swid.forEach((swid) => {
        if (!swid || swid.trim().length === 0) {
          throw new StixValidationError('SWID tags cannot be empty');
        }
      });
    }

    if (input.languages) {
      const languageRegex = /^[a-zA-Z]{2,3}(-[a-zA-Z]{2,3})?$/;
      input.languages.forEach((lang) => {
        if (!languageRegex.test(lang)) {
          throw new StixValidationError(`Invalid language format: ${lang}. Use ISO 639-2 or ISO 639-3 codes.`);
        }
      });
    }

    if (input.version) {
      const versionRegex = /^[0-9a-zA-Z.-]+$/;
      if (!versionRegex.test(input.version)) {
        throw new StixValidationError('Invalid version format');
      }
    }

    if (input.vendor && input.vendor.trim().length === 0) {
      throw new StixValidationError('Vendor name cannot be empty');
    }
  }

  async searchWithFilters(
    from: number = 0,
    size: number = 10,
    filters: SearchSoftwareInput = {}
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Software[];
  }> {
    try {
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      Object.entries(filters).forEach(([key, value]) => {
        if (value === undefined || value === null) return;

        switch (key) {
          case 'name':
          case 'cpe':
          case 'vendor':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'languages':
          case 'swid':
            if (Array.isArray(value)) {
              queryBuilder.query.bool.filter.push({ terms: { [key]: value } });
            }
            break;
          case 'created':
          case 'modified':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value, lte: value } },
              });
            }
            break;
          default:
            queryBuilder.query.bool.must.push({
              term: { [key]: value },
            });
        }
      });

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
          type: 'software' as const,
          name: hit._source.name,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),

        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search software',
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
                cpe: { type: 'keyword' },
                swid: { type: 'keyword' },
                languages: { type: 'keyword' },
                version: { type: 'keyword' },
                vendor: { type: 'text' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize software index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}