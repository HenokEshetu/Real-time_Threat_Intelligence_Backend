import { Inject, Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, } from '@opensearch-project/opensearch';
import { CreateNetworkTrafficInput, UpdateNetworkTrafficInput } from './network-traffic.input';
import { StixValidationError } from '../../../../core/exception/custom-exceptions';
import { SearchNetworkTrafficInput } from './network-traffic.resolver';
import { NetworkTraffic } from './network-traffic.entity';
import { BaseStixService } from '../../base-stix.service';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class NetworkTrafficService extends BaseStixService<NetworkTraffic> implements OnModuleInit {
  protected typeName = ' network-traffic';
  private readonly index = 'network-traffic';
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

  async create(createNetworkTrafficInput: CreateNetworkTrafficInput): Promise<NetworkTraffic> {
    this.validateNetworkTraffic(createNetworkTrafficInput);

    
    const now = new Date();

    const doc: NetworkTraffic = {
      ...createNetworkTrafficInput,

      id: createNetworkTrafficInput.id ,
      type: 'network-traffic' as const,
      spec_version: '2.1',
      created: now.toISOString(),
      modified: now.toISOString(),

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
        id: doc.id ,
        body: doc,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index document');
      }

      await this.publishCreated(doc)
      return doc;
    } catch (error) {
      throw new StixValidationError(`Failed to create network traffic: ${error.meta?.body?.error || error.message}`);
    }
  }

  async findOne(id: string): Promise<NetworkTraffic> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id,
        type: 'network-traffic' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date(),
        modified: source.modified || new Date(),

      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Network traffic with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch network traffic',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateNetworkTrafficInput: UpdateNetworkTrafficInput): Promise<NetworkTraffic> {
    this.validateNetworkTraffic(updateNetworkTrafficInput);

    try {
      const existing = await this.findOne(id);
      const updatedDoc: Partial<NetworkTraffic> = {
        ...updateNetworkTrafficInput,
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

      const updatedNetworkTraffic: NetworkTraffic = {
        ...existing,
        ...updatedDoc,
        spec_version: existing.spec_version || '2.1',
      };

      await this.publishUpdated(updatedNetworkTraffic);
      return updatedNetworkTraffic;

    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new StixValidationError(`Failed to update network traffic: ${error.meta?.body?.error || error.message}`);
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
        message: 'Failed to delete network traffic',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateNetworkTraffic(input: CreateNetworkTrafficInput | UpdateNetworkTrafficInput): void {
    if (input.protocols) {
      if (!Array.isArray(input.protocols)) {
        throw new StixValidationError('Protocols must be an array of strings');
      }
      for (const protocol of input.protocols) {
        if (typeof protocol !== 'string') {
          throw new StixValidationError('All protocols must be strings');
        }
        if (protocol !== protocol.toLowerCase()) {
          throw new StixValidationError('Protocols must be lowercase');
        }
      }
    }

    if (input.src_port !== undefined && (input.src_port < 0 || input.src_port > 65535)) {
      throw new StixValidationError('Source port must be between 0 and 65535');
    }
    if (input.dst_port !== undefined && (input.dst_port < 0 || input.dst_port > 65535)) {
      throw new StixValidationError('Destination port must be between 0 and 65535');
    }

    if (input.src_byte_count !== undefined && input.src_byte_count < 0) {
      throw new StixValidationError('Source byte count must be non-negative');
    }
    if (input.dst_byte_count !== undefined && input.dst_byte_count < 0) {
      throw new StixValidationError('Destination byte count must be non-negative');
    }
    if (input.src_packets !== undefined && input.src_packets < 0) {
      throw new StixValidationError('Source packets must be non-negative');
    }
    if (input.dst_packets !== undefined && input.dst_packets < 0) {
      throw new StixValidationError('Destination packets must be non-negative');
    }

    if (input.start && input.end) {
      const startDate = new Date(input.start);
      const endDate = new Date(input.end);
      if (startDate > endDate) {
        throw new StixValidationError('Start time must be before end time');
      }
    }
  }

  async searchWithFilters(
    from: number = 0,
    size: number = 10,
    filters: SearchNetworkTrafficInput = {}
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: NetworkTraffic[];
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

      Object.entries(filters).forEach(([key, value]) => {
        if (value === undefined || value === null) return;

        switch (key) {
          case 'protocols':
            if (Array.isArray(value)) {
              queryBuilder.query.bool.filter.push({
                terms: { [key]: value },
              });
            }
            break;
          case 'src_ref':
          case 'dst_ref':
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
            });
            break;
          case 'start':
          case 'end':
            if (value instanceof Date) {
              queryBuilder.query.bool.filter.push({
                range: { [key]: { gte: value, lte: value } },
              });
            }
            break;
          case 'src_port':
          case 'dst_port':
          case 'src_byte_count':
          case 'dst_byte_count':
          case 'src_packets':
          case 'dst_packets':
            queryBuilder.query.bool.filter.push({
              term: { [key]: value },
            });
            break;
          default:
            queryBuilder.query.bool.must.push({
              match: { [key]: { query: value, lenient: true } },
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
          type: 'network-traffic' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date(),
          modified: hit._source.modified || new Date(),

        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search network traffic',
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
                start: { type: 'date' },
                end: { type: 'date' },
                src_ref: { type: 'keyword' },
                dst_ref: { type: 'keyword' },
                src_port: { type: 'integer' },
                dst_port: { type: 'integer' },
                protocols: { type: 'keyword' },
                src_byte_count: { type: 'long' },
                dst_byte_count: { type: 'long' },
                src_packets: { type: 'long' },
                dst_packets: { type: 'long' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize network-traffic index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}