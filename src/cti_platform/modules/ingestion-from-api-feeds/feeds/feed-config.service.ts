import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { FeedProviderConfig } from './feed.types';
import { indicatorMappers } from './feed-mappers'; // Import mappers

@Injectable()
export class FeedConfigService {
  private readonly logger = new Logger(FeedConfigService.name);
  private readonly configFilePath: string = path.resolve(process.cwd(), 'config', 'feed-configs.json');
  private configs: FeedProviderConfig[] = [];

  constructor() {
    this.loadConfigs();
  }

  private async loadConfigs(): Promise<void> {
    try {
      if (!(await this.fileExists(this.configFilePath))) {
        this.logger.error(`Configuration file not found at ${this.configFilePath}`);
        throw new InternalServerErrorException('Feed configuration file missing');
      }
  
      const data = await fs.readFile(this.configFilePath, 'utf-8');
      const parsed = JSON.parse(data);
      if (!Array.isArray(parsed) || parsed.length === 0) {
        this.logger.error('Feed configuration file is empty or invalid');
        throw new InternalServerErrorException('Invalid feed configuration');
      }
      this.configs = this.parseConfigs(parsed);
      this.logger.log(`Loaded ${this.configs.length} feed configurations from ${this.configFilePath}`);
    } catch (error) {
      this.logger.error(`Failed to load feed configs: ${error instanceof Error ? error.stack : error}`);
      throw new InternalServerErrorException(`Failed to load feed configurations: ${error instanceof Error ? error.message : error}`);
    }
  }

  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath);
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
        indicatorMapper,
      };
    });
  }

  async getAllConfigs(): Promise<FeedProviderConfig[]> {
    return [...this.configs];
  }

  async getConfig(configId: string): Promise<FeedProviderConfig | null> {
    const config = this.configs.find(c => c.id === configId);
    if (!config) {
      this.logger.warn(`Feed config with ID ${configId} not found`);
      return null;
    }
    return { ...config };
  }
}