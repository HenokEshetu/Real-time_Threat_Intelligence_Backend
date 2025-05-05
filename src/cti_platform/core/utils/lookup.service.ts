import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { ConfigService } from '@nestjs/config';
import { createClient, RedisClientType } from 'redis';
import { v4 as uuidv4 } from 'uuid';

// Constants and types
const FIELD_TYPES = ['string', 'number', 'boolean'] as const;
type FieldType = typeof FIELD_TYPES[number];

interface StixIndexConfig {
  index: string;
  searchFields: string[];
  fieldType: FieldType;
}

interface SearchResult {
  index: string;
  source: any;
  id: string;
  score?: number;
}

@Injectable()
export class LookupService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(LookupService.name);
  private readonly openSearchClient: Client;
  private readonly redisClient: RedisClientType;
  private readonly debugLogging: boolean;
  private readonly cacheTtl: number;
  private readonly stixIndexMap: Map<string, StixIndexConfig>;
  private readonly searchFieldsMap: Map<string, StixIndexConfig>;
  private isRedisConnected: boolean = false;

  constructor(private readonly configService: ConfigService) {
    this.debugLogging = this.configService.get<string>('DEBUG_LOGGING', 'false') === 'true';
    this.cacheTtl = this.configService.get<number>('CACHE_TTL', 3600);

    // Initialize OpenSearch client
    this.openSearchClient = new Client({
      node: this.configService.get<string>('OPENSEARCH_NODE', 'http://localhost:9200'),
      auth: {
        username: this.configService.get<string>('OPENSEARCH_USERNAME', 'admin'),
        password: this.configService.get<string>('OPENSEARCH_PASSWORD', 'admin'),
      },
      ssl: { rejectUnauthorized: false }, // Add SSL config if needed
    });

    // Initialize Redis client
    this.redisClient = createClient({
      url: this.configService.get<string>('REDIS_URL', 'redis://localhost:6379'),
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 10) {
            this.logger.error('Redis reconnection failed after max retries');
            return new Error('Max retries reached');
          }
          return Math.min(retries * 100, 5000); // Exponential backoff up to 5s
        },
      },
    });

    this.setupRedisEventListeners();
    this.stixIndexMap = this.buildStixIndexMap();
    this.searchFieldsMap = this.buildSearchFieldsMap();
  }

  async onModuleInit() {
    try {
      await this.connectRedis();
      this.logger.log('LookupService initialized');
    } catch (error) {
      this.logger.error('Failed to initialize LookupService', {
        error: error instanceof Error ? error.message : error,
      });
    }
  }

  async onModuleDestroy() {
    try {
      if (this.isRedisConnected) {
        await this.redisClient.quit();
        this.logger.log('Redis client disconnected');
        this.isRedisConnected = false;
      }
    } catch (error) {
      this.logger.error('Failed to disconnect Redis client', {
        error: error instanceof Error ? error.message : error,
      });
    }
  }

  private async connectRedis(): Promise<void> {
    if (this.isRedisConnected) {
      return;
    }
    try {
      await this.redisClient.connect();
      this.isRedisConnected = true;
      this.logger.log('Redis client connected');
    } catch (error) {
      this.isRedisConnected = false;
      this.logger.error('Failed to connect to Redis', {
        error: error instanceof Error ? error.message : error,
      });
      throw error; // Let NestJS handle module initialization failure
    }
  }

  private setupRedisEventListeners(): void {
    this.redisClient.on('error', (err) => {
      this.isRedisConnected = false;
      this.logger.error(`Redis client error: ${err.message}`, { stack: err.stack });
    });

    this.redisClient.on('ready', () => {
      this.isRedisConnected = true;
      this.logger.log('Redis client ready');
    });

    this.redisClient.on('reconnecting', () => {
      this.logger.log('Redis client reconnecting...');
    });

    this.redisClient.on('end', () => {
      this.isRedisConnected = false;
      this.logger.warn('Redis client connection closed');
    });
  }

  private buildStixIndexMap(): Map<string, StixIndexConfig> {
    const map = new Map<string, StixIndexConfig>();
    const indexConfigs: Record<string, StixIndexConfig> = {
      // STIX Domain Objects (SDOs)
      'attack-pattern': {
        index: 'attack-patterns',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'campaign': {
        index: 'campaigns',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'course-of-action': {
        index: 'courses-of-action',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'grouping': {
        index: 'groupings',
        searchFields: ['name', 'description', 'context'],
        fieldType: 'string',
      },
      'identity': {
        index: 'identities',
        searchFields: ['name', 'description', 'identity_class'],
        fieldType: 'string',
      },
      'indicator': {
        index: 'indicators',
        searchFields: ['name', 'description', 'pattern'],
        fieldType: 'string',
      },
      'infrastructure': {
        index: 'infrastructures',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'intrusion-set': {
        index: 'intrusion-sets',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'location': {
        index: 'locations',
        searchFields: ['name', 'description', 'country', 'region'],
        fieldType: 'string',
      },
      'malware': {
        index: 'malwares',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'malware-analysis': {
        index: 'malware-analyses',
        searchFields: ['product', 'version'],
        fieldType: 'string',
      },
      'note': {
        index: 'notes',
        searchFields: ['content', 'abstract'],
        fieldType: 'string',
      },
      'observed-data': {
        index: 'observed-data',
        searchFields: ['description'],
        fieldType: 'string',
      },
      'opinion': {
        index: 'opinions',
        searchFields: ['explanation', 'opinion'],
        fieldType: 'string',
      },
      'report': {
        index: 'reports',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'threat-actor': {
        index: 'threat-actors',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'tool': {
        index: 'tools',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      'vulnerability': {
        index: 'vulnerabilities',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
      // STIX Cyber-observable Objects (SCOs)
      'artifact': {
        index: 'artifacts',
        searchFields: ['content'],
        fieldType: 'string',
      },
      'autonomous-system': {
        index: 'autonomous-systems',
        searchFields: ['number'],
        fieldType: 'number',
      },
      'directory': {
        index: 'directories',
        searchFields: ['path'],
        fieldType: 'string',
      },
      'domain-name': {
        index: 'domain-names',
        searchFields: ['value'],
        fieldType: 'string',
      },
      'email-addr': {
        index: 'email-addresses',
        searchFields: ['value', 'display_name'],
        fieldType: 'string',
      },
      'email-message': {
        index: 'email-messages',
        searchFields: ['subject', 'from_ref', 'to_refs'],
        fieldType: 'string',
      },
      'file': {
        index: 'files',
        searchFields: ['name', 'hashes'],
        fieldType: 'string',
      },
      'ipv4-addr': {
        index: 'ipv4-addresses',
        searchFields: ['value'],
        fieldType: 'string',
      },
      'ipv6-addr': {
        index: 'ipv6-addresses',
        searchFields: ['value'],
        fieldType: 'string',
      },
      'mac-addr': {
        index: 'mac-addresses',
        searchFields: ['value'],
        fieldType: 'string',
      },
      'mutex': {
        index: 'mutexes',
        searchFields: ['name'],
        fieldType: 'string',
      },
      'network-traffic': {
        index: 'network-traffic',
        searchFields: ['src_ref', 'dst_ref', 'protocols'],
        fieldType: 'string',
      },
      'process': {
        index: 'processes',
        searchFields: ['pid', 'command_line'],
        fieldType: 'string',
      },
      'software': {
        index: 'software',
        searchFields: ['name', 'vendor', 'version'],
        fieldType: 'string',
      },
      'url': {
        index: 'urls',
        searchFields: ['value'],
        fieldType: 'string',
      },
      'user-account': {
        index: 'user-accounts',
        searchFields: ['user_id', 'account_login', 'display_name'],
        fieldType: 'string',
      },
      'windows-registry-key': {
        index: 'windows-registry-keys',
        searchFields: ['key'],
        fieldType: 'string',
      },
      'x509-certificate': {
        index: 'x509-certificates',
        searchFields: ['issuer', 'subject', 'serial_number'],
        fieldType: 'string',
      },
      // STIX Relationship Objects (SROs)
      'relationship': {
        index: 'relationships',
        searchFields: ['source_ref', 'target_ref', 'relationship_type'],
        fieldType: 'string',
      },
      'sighting': {
        index: 'sightings',
        searchFields: ['description', 'sighting_of_ref'],
        fieldType: 'string',
      },
      // STIX Meta Objects
      'language-content': {
        index: 'language-contents',
        searchFields: ['content'],
        fieldType: 'string',
      },
      'marking-definition': {
        index: 'marking-definitions',
        searchFields: ['name', 'definition_type'],
        fieldType: 'string',
      },
      'extension-definition': {
        index: 'extension-definitions',
        searchFields: ['name', 'description'],
        fieldType: 'string',
      },
    };

    Object.entries(indexConfigs).forEach(([type, config]) => {
      map.set(type, config);
    });

    return map;
  }

  private buildSearchFieldsMap(): Map<string, StixIndexConfig> {
    const map = new Map<string, StixIndexConfig>();
    this.stixIndexMap.forEach((config, type) => {
      map.set(config.index, { ...config, index: config.index });
    });
    return map;
  }

  private isCompatible(value: string, type: FieldType): boolean {
    if (!value?.trim()) return false;

    switch (type) {
      case 'number':
        return !isNaN(Number(value)) && value.trim() !== '';
      case 'boolean':
        return ['true', 'false'].includes(value.toLowerCase());
      case 'string':
      default:
        return true;
    }
  }

  private async ensureRedisConnected(): Promise<void> {
    if (!this.isRedisConnected) {
      try {
        await this.connectRedis();
      } catch (error) {
        this.logger.warn('Redis reconnection failed, proceeding without cache', {
          error: error instanceof Error ? error.message : error,
        });
      }
    }
  }

  private async getFromCache<T>(key: string): Promise<T | null> {
    await this.ensureRedisConnected();
    if (!this.isRedisConnected) {
      this.logger.warn(`Cache read skipped for key: ${key} due to disconnected Redis client`);
      return null;
    }

    try {
      const cached = await this.redisClient.get(key);
      if (cached) {
        if (this.debugLogging) {
          this.logger.debug(`Cache hit for key: ${key}`);
        }
        return JSON.parse(cached) as T;
      }
      return null;
    } catch (error) {
      this.logger.warn(`Cache read failed for key: ${key}`, {
        error: error instanceof Error ? error.message : error,
      });
      return null;
    }
  }

  private async setCache(key: string, value: any, ttl: number): Promise<void> {
    await this.ensureRedisConnected();
    if (!this.isRedisConnected) {
      this.logger.warn(`Cache write skipped for key: ${key} due to disconnected Redis client`);
      return;
    }

    try {
      await this.redisClient.setEx(key, ttl, JSON.stringify(value));
      if (this.debugLogging) {
        this.logger.debug(`Cache set for key: ${key} with TTL: ${ttl}s`);
      }
    } catch (error) {
      this.logger.warn(`Cache write failed for key: ${key}`, {
        error: error instanceof Error ? error.message : error,
      });
    }
  }

  private getSearchConfig(type?: string): StixIndexConfig[] {
    if (type && this.stixIndexMap.has(type)) {
      return [this.stixIndexMap.get(type)!];
    }
    return Array.from(this.stixIndexMap.values());
  }

  private buildSearchQuery(value: string, fields: string[], type: FieldType) {
    const boostFactor = 2.0;
    const fuzziness = type === 'string' ? 'AUTO' : 0;

    const query: any = {
      query: {
        bool: {
          should: [
            {
              multi_match: {
                query: value,
                fields: fields,
                type: 'phrase',
                boost: boostFactor,
              },
            },
            ...(type === 'string'
              ? [
                  {
                    multi_match: {
                      query: value,
                      fields: fields,
                      fuzziness: fuzziness,
                      prefix_length: 2,
                    },
                  },
                ]
              : []),
          ],
          minimum_should_match: 1,
        },
      },
      size: 5,
      _source: ['id', 'type', 'name', 'value', 'pattern'],
    };

    return query;
  }

  async findByValue(value: string, type?: string): Promise<any | null> {
    if (!value?.trim()) {
      this.logger.warn('Empty or invalid search value provided');
      return null;
    }

    const searchId = uuidv4().substring(0, 8);
    const cacheKey = `lookup:${type || 'all'}:${value}`;

    const cached = await this.getFromCache<any>(cacheKey);
    if (cached) {
      return cached;
    }

    const startTime = Date.now();
    const searchConfigs = this.getSearchConfig(type);

    if (this.debugLogging) {
      this.logger.debug(`[${searchId}] Starting search for "${value}"`, {
        type,
        indexes: searchConfigs.map((c) => c.index),
        searchFields: searchConfigs.flatMap((c) => c.searchFields),
      });
    }

    try {
      const searchPromises = searchConfigs.map(async (config) => {
        if (!this.isCompatible(value, config.fieldType)) {
          if (this.debugLogging) {
            this.logger.debug(`[${searchId}] Skipping incompatible type`, {
              index: config.index,
              fieldType: config.fieldType,
            });
          }
          return null;
        }

        try {
          const query = this.buildSearchQuery(value, config.searchFields, config.fieldType);
          const response = await this.openSearchClient.search({
            index: config.index,
            body: query,
          });

          const hits = response.body.hits?.hits || [];
          if (hits.length > 0) {
            const bestMatch = hits[0];
            if (this.debugLogging) {
              this.logger.debug(`[${searchId}] Found match in ${config.index}`, {
                score: bestMatch._score,
                id: bestMatch._id,
              });
            }
            return {
              index: config.index,
              source: bestMatch._source,
              id: bestMatch._id,
              score: bestMatch._score,
            };
          }
          return null;
        } catch (error) {
          this.logger.warn(`[${searchId}] Search failed in index ${config.index}`, {
            error: error instanceof Error ? error.message : error,
          });
          return null;
        }
      });

      const results = await Promise.all(searchPromises);
      const validResults = results.filter(Boolean) as SearchResult[];

      if (validResults.length === 0) {
        if (this.debugLogging) {
          this.logger.debug(`[${searchId}] No matches found for "${value}"`);
        }
        await this.setCache(cacheKey, null, this.cacheTtl / 2);
        return null;
      }

      const bestMatch = validResults.reduce((prev, current) =>
        (prev.score || 0) > (current.score || 0) ? prev : current
      );

      const searchTime = Date.now() - startTime;
      this.logger.log(`[${searchId}] Found best match in ${bestMatch.index} (${searchTime}ms)`, {
        id: bestMatch.id,
        score: bestMatch.score,
      });

      await this.setCache(cacheKey, bestMatch.source, this.cacheTtl);
      return bestMatch.source;
    } catch (error) {
      this.logger.error(`[${searchId}] Search failed for "${value}"`, {
        error: error instanceof Error ? error.message : error,
        stack: error instanceof Error ? error.stack : undefined,
      });
      throw error;
    }
  }

  async findByValues(values: string[], type?: string): Promise<Map<string, any>> {
    const results = new Map<string, any>();
    await Promise.all(
      values.map(async (value) => {
        const result = await this.findByValue(value, type);
        if (result) {
          results.set(value, result);
        }
      })
    );
    return results;
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.ensureRedisConnected();
      const [osHealthy, redisHealthy] = await Promise.all([
        this.openSearchClient.ping().then(() => true).catch(() => false),
        this.redisClient.ping().then(() => true).catch(() => false),
      ]);
      return osHealthy && redisHealthy;
    } catch {
      return false;
    }
  }
}