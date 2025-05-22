import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  OnModuleInit,
  Inject,
  Logger,
} from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import {
  CreateIndicatorInput,
  UpdateIndicatorInput,
  SearchIndicatorInput,
} from './indicator.input';
import { Indicator } from './indicator.entity';
import { BaseStixService } from '../../base-stix.service';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { generateStixId } from '../../stix-id-generator';

@Injectable()
export class IndicatorService
  extends BaseStixService<Indicator>
  implements OnModuleInit
{
  protected typeName = 'indicator';
  private readonly index = 'indicators';
  private readonly logger = new Logger(IndicatorService.name);

  constructor(
    @Inject(PUB_SUB) pubSub: RedisPubSub,
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client,
  ) {
    super(pubSub);
  }

  async onModuleInit(): Promise<void> {
    try {
      await this.ensureIndex();
      this.logger.log('IndicatorService initialized and index verified');
    } catch (error) {
      this.logger.error('Failed to initialize IndicatorService', error.stack);
      throw error;
    }
  }

  private normalizeIndicatorDates(indicator: Partial<Indicator>): Indicator {
    const now = new Date().toISOString();
    return {
      ...indicator,
      id: indicator.id || generateStixId('indicator', indicator),
      pattern: indicator.pattern || '',
      pattern_type: indicator.pattern_type || 'stix',
      pattern_version: indicator.pattern_version || '2.1',
      type: 'indicator',
      spec_version: indicator.spec_version || '2.1',
      created: indicator.created || now,
      modified: now,
      valid_from: indicator.valid_from
        ? new Date(indicator.valid_from)
        : new Date(),
      valid_until: indicator.valid_until
        ? new Date(indicator.valid_until)
        : new Date(),
    } as Indicator;
  }

  private validatePattern(pattern: string, patternType: string): void {
    if (!pattern || !patternType) {
      throw new InternalServerErrorException(
        'Pattern and pattern_type are required',
      );
    }

    try {
      // Basic validation for STIX patterns
      if (patternType.toLowerCase() === 'stix') {
        if (!pattern.startsWith('[') || !pattern.endsWith(']')) {
          throw new Error('STIX pattern must be enclosed in square brackets');
        }

        const patternParts = pattern.split('=');
        if (patternParts.length !== 2) {
          throw new Error('STIX pattern must contain exactly one equals sign');
        }

        const [leftSide, rightSide] = patternParts;
        if (!leftSide.trim() || !rightSide.trim()) {
          throw new Error('Both sides of the STIX pattern must contain values');
        }
      }
    } catch (error) {
      throw new InternalServerErrorException(
        `Invalid ${patternType} pattern: ${error.message}`,
      );
    }
  }

  private validateIndicatorInput(input: CreateIndicatorInput): void {
    // Validate required fields
    this.validatePattern(input.pattern, input.pattern_type);

    // Validate optional fields if provided
    if (input.valid_from && isNaN(new Date(input.valid_from).getTime())) {
      throw new InternalServerErrorException(
        'Invalid valid_from: must be a valid date',
      );
    }
    if (input.valid_until && isNaN(new Date(input.valid_until).getTime())) {
      throw new InternalServerErrorException(
        'Invalid valid_until: must be a valid date',
      );
    }
    if (input.indicator_types && !Array.isArray(input.indicator_types)) {
      throw new InternalServerErrorException(
        'Invalid indicator_types: must be an array',
      );
    }
    if (input.kill_chain_phases && !Array.isArray(input.kill_chain_phases)) {
      throw new InternalServerErrorException(
        'Invalid kill_chain_phases: must be an array',
      );
    }
  }

  async create(createIndicatorInput: CreateIndicatorInput): Promise<Indicator> {
    this.logger.debug(
      `Creating indicator with input: ${JSON.stringify(createIndicatorInput, null, 2)}`,
    );

    try {
      // Validate input
      this.validatePattern(
        createIndicatorInput.pattern,
        createIndicatorInput.pattern_type,
      );

      const indicator = this.normalizeIndicatorDates({
        ...createIndicatorInput,
      });

      // Check if document already exists
      const exists = await this.openSearchService.exists({
        index: this.index,
        id: indicator.id,
      });

      if (exists.body) {
        this.logger?.warn(`Document already exists`, { id: indicator.id });

        const existingDoc = await this.findOne(indicator.id);
        return existingDoc;
      }

      this.logger.log(
        `Creating indicator ${indicator.id} with pattern: ${indicator.pattern}`,
      );

      const response = await this.openSearchService.index({
        index: this.index,
        id: indicator.id,
        body: indicator,
        refresh: 'wait_for',
        op_type: 'create',
      });

      // Handle both 'created' and 'updated' responses
      if (
        response.body.result === 'created' ||
        response.body.result === 'updated'
      ) {
        this.logger.log(
          `Successfully ${response.body.result} indicator ${indicator.id}`,
        );
        await this.publishCreated(indicator);
        return indicator;
      }

      this.logger.error(
        `Unexpected OpenSearch response: ${JSON.stringify(response.body)}`,
      );
      throw new Error(
        `Unexpected OpenSearch response: ${response.body.result}`,
      );
    } catch (error) {
      this.logger.error(
        `Failed to create indicator: ${error.message}`,
        error.stack,
      );
      throw this.handleOpenSearchError(error, 'create indicator');
    }
  }

  async findOne(id: string): Promise<Indicator> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return this.transformOpenSearchResponse(response);
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Indicator with ID ${id} not found`);
      }
      throw this.handleOpenSearchError(error, 'fetch indicator');
    }
  }

  async update(
    id: string,
    updateIndicatorInput: UpdateIndicatorInput,
  ): Promise<Indicator> {
    try {
      const existingIndicator = await this.findOne(id);
      // Validate input
      const mergedInput = {
        ...existingIndicator,
        ...updateIndicatorInput,
        pattern: updateIndicatorInput.pattern || existingIndicator.pattern,
        pattern_type:
          updateIndicatorInput.pattern_type || existingIndicator.pattern_type,
      };
      this.validateIndicatorInput(mergedInput);

      const updatedIndicator = this.normalizeIndicatorDates(mergedInput);

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedIndicator },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update indicator');
      }

      await this.publishUpdated(updatedIndicator);
      return updatedIndicator;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw this.handleOpenSearchError(error, 'update indicator');
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });

      const success = response.body.result === 'deleted';
      if (success) {
        await this.publishDeleted(id);
      }
      return success;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw this.handleOpenSearchError(error, 'delete indicator');
    }
  }

  async searchWithFilters(
    filters: SearchIndicatorInput = {},
    page: number = 1,
    pageSize: number = 10,
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Indicator[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const query = this.buildSearchQuery(filters);

      const response = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: query,
      });

      return this.transformSearchResponse(response, page, pageSize);
    } catch (error) {
      throw this.handleOpenSearchError(error, 'search indicators');
    }
  }

  private buildSearchQuery(filters: SearchIndicatorInput): any {
    const query: { query: any; sort?: any[] } = {
      query: { bool: { must: [], filter: [], should: [] } },
      sort: [{ modified: { order: 'desc' } }],
    };

    Object.entries(filters).forEach(([key, value]) => {
      if (!value) return;

      if (Array.isArray(value)) {
        query.query.bool.filter.push({ terms: { [key]: value } });
      } else if (typeof value === 'boolean' || typeof value === 'number') {
        query.query.bool.filter.push({ term: { [key]: value } });
      } else if (
        ['created', 'modified', 'valid_from', 'valid_until'].includes(key)
      ) {
        this.addDateRangeQuery(query, key, value);
      } else if (typeof value === 'string') {
        this.addStringQuery(query, key, value);
      }
    });

    this.finalizeQueryStructure(query);
    return query;
  }

  private addDateRangeQuery(query: any, key: string, value: any): void {
    if (typeof value === 'object' && ('gte' in value || 'lte' in value)) {
      query.query.bool.filter.push({ range: { [key]: value } });
    } else if (value instanceof Date) {
      query.query.bool.filter.push({
        range: {
          [key]: { gte: value.toISOString(), lte: value.toISOString() },
        },
      });
    }
  }

  private addStringQuery(query: any, key: string, value: string): void {
    if (value.includes('*')) {
      query.query.bool.must.push({ wildcard: { [key]: value.toLowerCase() } });
    } else if (value.includes('~')) {
      query.query.bool.should.push({
        fuzzy: { [key]: { value: value.replace('~', ''), fuzziness: 'AUTO' } },
      });
    } else {
      query.query.bool.must.push({ match_phrase: { [key]: value } });
    }
  }

  private finalizeQueryStructure(query: any): void {
    if (
      !query.query.bool.must.length &&
      !query.query.bool.filter.length &&
      !query.query.bool.should.length
    ) {
      query.query = { match_all: {} };
    } else if (query.query.bool.should.length > 0) {
      query.query.bool.minimum_should_match = 1;
    }
  }

  private transformOpenSearchResponse(response: any): Indicator {
    const source = response.body._source;
    return {
      ...source,
      id: response.body._id,
      type: 'indicator',
      spec_version: source.spec_version || '2.1',
      valid_from: source.valid_from ? new Date(source.valid_from) : new Date(),
      valid_until: source.valid_until
        ? new Date(source.valid_until)
        : new Date(),
      created: source.created || new Date().toISOString(),
      modified: source.modified || new Date().toISOString(),
    };
  }

  private transformSearchResponse(
    response: any,
    page: number,
    pageSize: number,
  ) {
    const total =
      typeof response.body.hits.total === 'number'
        ? response.body.hits.total
        : (response.body.hits.total?.value ?? 0);

    return {
      page,
      pageSize,
      total,
      totalPages: Math.ceil(total / pageSize),
      results: response.body.hits.hits.map((hit) =>
        this.transformOpenSearchResponse({
          body: {
            _id: hit._id,
            _source: hit._source,
          },
        }),
      ),
    };
  }

  private handleOpenSearchError(
    error: any,
    operation: string,
  ): InternalServerErrorException {
    let details = error.message;
    let errorType = 'UnknownError';

    if (error.meta?.body?.error) {
      errorType = error.meta.body.error.type || 'OpenSearchError';
      details =
        error.meta.body.error.reason || JSON.stringify(error.meta.body.error);
    }

    this.logger.error(
      `OpenSearch ${operation} error (${errorType}): ${details}`,
    );

    return new InternalServerErrorException({
      message: `Failed to ${operation}`,
      details,
      errorType,
    });
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchService.indices.exists({
        index: this.index,
      });
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
                description: { type: 'text' },
                indicator_types: { type: 'keyword' },
                pattern: { type: 'text' },
                pattern_type: { type: 'keyword' },
                pattern_version: { type: 'keyword' },
                valid_from: { type: 'date' },
                valid_until: { type: 'date' },
                kill_chain_phases: { type: 'nested' },
                labels: { type: 'keyword' },
                confidence: { type: 'integer' },
                external_references: { type: 'nested' },
                object_marking_refs: { type: 'keyword' },
                granular_markings: { type: 'nested' },
                extensions: { type: 'object', dynamic: 'true' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw this.handleOpenSearchError(error, 'initialize indicators index');
    }
  }
}
