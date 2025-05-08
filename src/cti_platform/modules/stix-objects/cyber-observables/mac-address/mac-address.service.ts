import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateMACAddressInput, UpdateMACAddressInput } from './mac-address.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchMACAddressInput } from './mac-address.resolver';
import { MACAddress } from './mac-address.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class MACAddressService extends BaseStixService<MACAddress> implements OnModuleInit {
  private readonly logger = console; // Replace with a proper logger if available
  protected typeName = ' mac-addr';
  private readonly index = 'mac-addresses';


  constructor(
            @Inject(PUB_SUB) pubSub: RedisPubSub,
            @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client
          ) {
            super(pubSub);
          }

  async onModuleInit() {
    await this.ensureIndex();}

  async create(createMACAddressInput: CreateMACAddressInput): Promise<MACAddress> {
    
    const now = new Date();

    const doc: MACAddress = {
      ...createMACAddressInput,
      
      type: 'mac-addr' as const,
      spec_version: '2.1',
      created: now.toISOString(),
      modified: now.toISOString(),
      value: createMACAddressInput.value, // Required field
      
    };

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


    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: doc.id || uuidv4(),
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }
      await this.publishCreated(doc);
      return doc;
    } catch (error) {
      throw new StixValidationError(`Failed to create MAC address: ${error.meta?.body?.error || error.message}`);
    }
  }

  async findOne(id: string): Promise<MACAddress> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id,
        type: 'mac-addr' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),
        value: source.value, // Ensure required field is included
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`MAC address with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch MAC address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateMACAddressInput: UpdateMACAddressInput): Promise<MACAddress> {
    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<MACAddress> = {
        ...updateMACAddressInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
        retry_on_conflict: 3,
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update document');
      }

      const updatedMACAddress: MACAddress = {
                            ...existing,
                            ...updatedDoc,
                            
                            spec_version: existing.spec_version || '2.1',
                          };
                          await this.publishUpdated(updatedMACAddress);
                  return updatedMACAddress;

      
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new StixValidationError(`Failed to update MAC address: ${error.meta?.body?.error || error.message}`);
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
        message: 'Failed to delete MAC address',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    from: number = 0,
    size: number = 10,
    filter: SearchMACAddressInput = {}
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: MACAddress[];
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

      for (const [key, value] of Object.entries(filter)) {
        if (value === undefined || value === null) continue;

        switch (key) {
          case 'value':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
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
          type: 'mac-addr' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),
          value: hit._source.value, // Ensure required field is included
          
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search MAC addresses',
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
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                value: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize mac-addresses index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}