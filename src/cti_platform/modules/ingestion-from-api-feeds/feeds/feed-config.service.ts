import { Injectable, Logger, InternalServerErrorException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { FeedProviderConfig } from './feed.types';

@Injectable()
export class FeedConfigService {
  private readonly logger = new Logger(FeedConfigService.name);
  private readonly configFilePath: string = path.resolve(process.cwd(), 'config', 'feed-configs.json');
  private configs: FeedProviderConfig[] = [];

  constructor() {
    this.loadConfigs();
  }

  /**
   * Loads the configurations from the file during initialization, falling back to an empty array if the file is missing.
   */
  private async loadConfigs(): Promise<void> {
    try {
      if (!(await this.fileExists(this.configFilePath))) {
        this.logger.warn(`Configuration file not found at ${this.configFilePath}. Starting with no feed configurations. Please create the file to add feeds.`);
        this.configs = [];
        return;
      }

      const data = await fs.readFile(this.configFilePath, 'utf-8');
      this.configs = this.parseConfigs(JSON.parse(data));
      this.logger.log(`Loaded ${this.configs.length} feed configurations from ${this.configFilePath}`);
    } catch (error) {
      this.logger.error(`Failed to load feed configs from ${this.configFilePath}: ${error instanceof Error ? error.stack : error}`);
      this.logger.warn(`Continuing with no feed configurations due to load failure.`);
      this.configs = [];
    }
  }

  /**
   * Checks if a file exists.
   */
  private async fileExists(filePath: string): Promise<boolean> {
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Parses configurations from JSON, reconstructing the indicatorMapper function.
   */
  private parseConfigs(data: any[]): FeedProviderConfig[] {
    return data.map(source => {
      const indicatorMapperStr = source.indicatorMapper;
      let indicatorMapper;

      try {
        indicatorMapper = eval(`(${indicatorMapperStr})`);
        if (typeof indicatorMapper !== 'function') {
          throw new Error('Invalid indicatorMapper format');
        }
      } catch (error) {
        this.logger.warn(`Failed to parse indicatorMapper for ${source.id}: ${error.message}. Using default mapper.`);
        indicatorMapper = (raw: any) => ({
          id: raw.id || require('uuid').v4(),
          indicator: raw.value || raw.indicator || raw.ioc,
          type: raw.type || 'unknown',
          description: raw.description || '',
          created: raw.created || new Date().toISOString(),
          modified: raw.modified || new Date().toISOString(),
        });
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

  /**
   * Retrieves all feed provider configurations.
   */
  async getAllConfigs(): Promise<FeedProviderConfig[]> {
    return [...this.configs]; // Return a copy to prevent external modification
  }

  /**
   * Retrieves a specific feed provider configuration by ID.
   */
  async getConfig(configId: string): Promise<FeedProviderConfig | null> {
    const config = this.configs.find(c => c.id === configId);
    if (!config) {
      this.logger.warn(`Feed config with ID ${configId} not found`);
      return null;
    }
    return { ...config }; // Return a copy to prevent external modification
  }
}