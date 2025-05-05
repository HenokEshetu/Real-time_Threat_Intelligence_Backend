import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v5 as uuidv5 } from 'uuid';
import moment from 'moment';
import { FeedProviderConfig, GenericStixObject, StixType } from './feed.types';
import { objectMappers } from './feed-mappers';

// Constants from feed-mappers.ts
const STIX_VERSION = '2.1';
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
const TLP_MARKINGS = {
  white: {
    id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    type: 'marking-definition',
    spec_version: STIX_VERSION,
    created: '2017-01-20T00:00:00.000Z',
    definition_type: 'tlp',
    definition: { tlp: 'white' },
  },
};

// Utility function from feed-mappers.ts
const generateStixId = (type: string, value: string): string => {
  return `${type}--${uuidv5(value, NAMESPACE)}`;
};

// Create TLP marking (simplified from feed-mappers.ts)
const createTLPMarking = (tlp: 'white' | 'green' | 'amber' | 'red', timestamp: number): GenericStixObject => ({
  id: generateStixId('marking-definition', `tlp_${tlp}_${timestamp}`),
  type: 'marking-definition',
  spec_version: STIX_VERSION,
  created: moment(timestamp * 1000).toISOString(),
  definition_type: 'tlp',
  definition: { tlp },
});

@Injectable()
export class FeedConfigService {
  private readonly logger = new Logger(FeedConfigService.name);
  private readonly configFilePath: string = path.resolve(process.cwd(), 'config', 'feed-configs.json');
  private configs: FeedProviderConfig[] = [];
  private isInitialized: Promise<void>;

  constructor() {
    this.isInitialized = this.loadConfigs();
  }

  async onModuleInit() {
    await this.isInitialized;
  }

  private async loadConfigs(): Promise<void> {
    try {
      if (!(await this.fileExists(this.configFilePath))) {
        this.logger.warn(`Configuration file not found at ${this.configFilePath}, using empty config`);
        this.configs = [];
        return;
      }

      const data = await fs.readFile(this.configFilePath, 'utf-8');
      if (!data.trim()) {
        this.logger.warn('Feed configuration file is empty, using empty config');
        this.configs = [];
        return;
      }

      let parsed;
      try {
        parsed = JSON.parse(data);
      } catch (parseError) {
        this.logger.error('Failed to parse feed-configs.json, using empty config', {
          error: parseError instanceof Error ? parseError.message : parseError,
          fileContent: data.substring(0, 100),
          stack: parseError instanceof Error ? parseError.stack : undefined,
        });
        this.configs = [];
        return;
      }

      if (!Array.isArray(parsed) || parsed.length === 0) {
        this.logger.warn('Feed configuration file is empty or not an array, using empty config', { parsed });
        this.configs = [];
        return;
      }

      this.configs = this.parseConfigs(parsed);
      this.logger.log(`Loaded ${this.configs.length} feed configurations from ${this.configFilePath}`);
    } catch (error) {
      this.logger.error('Unexpected error loading feed configs, using empty config', {
        error: error instanceof Error ? error.message : error,
        stack: error instanceof Error ? error.stack : undefined,
      });
      this.configs = [];
    }
  }

  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath, fs.constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  private parseConfigs(data: any[]): FeedProviderConfig[] {
    this.logger.log('Available indicator mappers:', Object.keys(objectMappers));
    return data
      .filter((source) => this.validateConfig(source))
      .map((source) => {
        const objectMapperName = source.objectMapper;
        const objectMapper = objectMappers[objectMapperName];

        this.logger.log(`Mapper for ${source.id}:`, {
          objectMapperName,
          isFunction: typeof objectMapper === 'function',
        });

        if (!objectMapper) {
          this.logger.warn(
            `object mapper '${objectMapperName}' for ${source.id} not found. Using fallback observed-data mapper. Available mappers: ${Object.keys(
              objectMappers,
            ).join(', ')}`,
          );
          return {
            id: source.id,
            name: source.name,
            apiUrl: source.apiUrl,
            apiKeyEnv: source.apiKeyEnv,
            headers: source.headers,
            method: source.method || 'GET',
            params: source.params,
            data: source.data,
            responsePath: source.responsePath,
            batchSize: source.batchSize || 100,
            timeout: source.timeout || 30000,
            rateLimitDelay: source.rateLimitDelay || 1000,
            maxRetries: source.maxRetries || 3,
            schedule: source.schedule || '*/59 * * * *',
            pagination: source.pagination,
            objectMapper: (raw: any): GenericStixObject[] => {
              const timestamp = Math.floor(Date.now() / 1000);
              const tlpMarking = createTLPMarking('white', timestamp);
              const value = raw.value || raw.indicator || raw.ioc || 'unknown';
              const id = generateStixId('observed-data', raw.id || value || uuidv5('fallback', NAMESPACE));
              const observedData: GenericStixObject = {
                id,
                type: 'observed-data' as StixType,
                spec_version: STIX_VERSION,
                number_observed: 1,
                first_observed: moment(timestamp * 1000).toISOString(),
                last_observed: moment(timestamp * 1000).toISOString(),
                created: raw.created ? moment(raw.created).toISOString() : moment(timestamp * 1000).toISOString(),
                modified: raw.modified ? moment(raw.modified).toISOString() : moment(timestamp * 1000).toISOString(),
                description: raw.description || `Fallback observed-data for unmapped feed data: ${value}`,
                labels: ['feed-fallback', `source:${source.name.toLowerCase()}`],
                object_marking_refs: [tlpMarking.id],
                indicator: raw.value || raw.indicator || raw.ioc || 'unknown',
              };
              return [observedData, tlpMarking];
            },
          };
        }

        return {
          id: source.id,
          name: source.name,
          apiUrl: source.apiUrl,
          apiKeyEnv: source.apiKeyEnv,
          headers: source.headers,
          method: source.method || 'GET',
          params: source.params,
          data: source.data,
          responsePath: source.responsePath,
          batchSize: source.batchSize || 100,
          timeout: source.timeout || 30000,
          rateLimitDelay: source.rateLimitDelay || 1000,
          maxRetries: source.maxRetries || 3,
          schedule: source.schedule || '*/59 * * * *',
          pagination: source.pagination,
          objectMapper,
        };
      });
  }

  private validateConfig(source: any): boolean {
    const requiredFields = ['id', 'name', 'apiUrl', 'apiKeyEnv', 'objectMapper'];
    const missingFields = requiredFields.filter((field) => !source[field]);

    if (missingFields.length > 0) {
      this.logger.error(`Invalid feed config: missing required fields ${missingFields.join(', ')}`, { config: source });
      return false;
    }

    if (!source.apiUrl.startsWith('http')) {
      this.logger.error(`Invalid feed config: apiUrl must be a valid URL`, { config: source });
      return false;
    }

    return true;
  }

  async getAllConfigs(): Promise<FeedProviderConfig[]> {
    await this.isInitialized;
    return [...this.configs];
  }

  async getConfig(configId: string): Promise<FeedProviderConfig | null> {
    await this.isInitialized;
    const config = this.configs.find((c) => c.id === configId);
    if (!config) {
      this.logger.warn(`Feed config with ID ${configId} not found`);
      return null;
    }
    return { ...config };
  }
}