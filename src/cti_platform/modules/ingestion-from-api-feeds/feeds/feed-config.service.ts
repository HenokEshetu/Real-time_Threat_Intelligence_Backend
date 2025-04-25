import { Injectable, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { FeedProviderConfig } from './feed.types';
import { indicatorMappers } from './feed-mappers';

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
        this.logger.warn('Failed to parse feed-configs.json, using empty config', {
          error: parseError instanceof Error ? parseError.message : parseError,
          fileContent: data.substring(0, 100),
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
        error: error instanceof Error ? error.stack : error,
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
    return data.map(source => {
      const indicatorMapperName = source.indicatorMapper;
      const indicatorMapper = indicatorMappers[indicatorMapperName];

      if (!indicatorMapper) {
        this.logger.warn(`Indicator mapper '${indicatorMapperName}' for ${source.id} not found. Using default mapper.`);
        return {
          id: source.id,
          name: source.name,
          apiUrl: source.apiUrl,
          apiKeyEnv: source.apiKeyEnv,
          headers: source.headers,
          method: source.method,
          params: source.params,
          data: source.data,
          responsePath: source.responsePath,
          batchSize: source.batchSize,
          timeout: source.timeout,
          rateLimitDelay: source.rateLimitDelay,
          maxRetries: source.maxRetries,
          schedule: source.schedule,
          pagination: source.pagination,
          indicatorMapper: (raw: any) => ({
            id: raw.id || require('uuid').v4(),
            indicator: raw.value || raw.indicator || raw.ioc,
            type: raw.type || 'unknown',
            description: raw.description || '',
            created: raw.created || new Date().toISOString(),
            modified: raw.modified || new Date().toISOString(),
          }),
        };
      }

      return {
        id: source.id,
        name: source.name,
        apiUrl: source.apiUrl,
        apiKeyEnv: source.apiKeyEnv,
        headers: source.headers,
        method: source.method,
        params: source.params,
        data: source.data,
        responsePath: source.responsePath,
        batchSize: source.batchSize,
        timeout: source.timeout,
        rateLimitDelay: source.rateLimitDelay,
        maxRetries: source.maxRetries,
        schedule: source.schedule,
        pagination: source.pagination,
        indicatorMapper,
      };
    });
  }

  async getAllConfigs(): Promise<FeedProviderConfig[]> {
    await this.isInitialized;
    return [...this.configs];
  }

  async getConfig(configId: string): Promise<FeedProviderConfig | null> {
    await this.isInitialized;
    const config = this.configs.find(c => c.id === configId);
    if (!config) {
      this.logger.warn(`Feed config with ID ${configId} not found`);
      return null;
    }
    return { ...config };
  }
}