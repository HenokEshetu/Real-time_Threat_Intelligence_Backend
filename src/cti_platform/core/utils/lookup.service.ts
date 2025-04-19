// src/services/lookup.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { ConfigService } from '@nestjs/config';
import { createClient, RedisClientType } from 'redis';

const FIELD_TYPES = ['string', 'number', 'boolean'] as const;
type FieldType = typeof FIELD_TYPES[number];

const STIX_INDEXES: Record<string, string> = {
  'artifact': 'artifacts',
  'autonomous-system': 'autonomous-systems',
  'directory': 'directories',
  'domain-name': 'domain-names',
  'email-address': 'email-addresses',
  'email-message': 'email-messages',
  'file': 'files',
  'ipv4-addr': 'ipv4-addresses',
  'ipv6-addr': 'ipv6-addresses',
  'mac-address': 'mac-addresses',
  'mutex': 'mutexes',
  'network-traffic': 'network-traffic',
  'process': 'process',
  'software': 'software',
  'url': 'urls',
  'user-account': 'user-accounts',
  'windows-registry-key': 'windows-registry-keys',
  'x509-certificate': 'x509-certificates',
  'attack-pattern': 'attack-patterns',
  'campaign': 'campaigns',
  'course-of-action': 'course-of-actions',
  'grouping': 'groupings',
  'identity': 'identities',
  'incident': 'incidents',
  'indicator': 'indicators',
  'infrastructure': 'infrastructures',
  'intrusion-set': 'intrusion-sets',
  'location': 'locations',
  'malware': 'malware',
  'malware-analysis': 'malware-analysis',
  'note': 'notes',
  'observed-data': 'observed-data',
  'opinion': 'opinions',
  'report': 'reports',
  'threat-actor': 'threat-actors',
  'tool': 'tools',
  'vulnerability': 'vulnerabilities',
  'sighting': 'sightings',
};

const SEARCH_FIELDS: Record<string, { fields: string[]; type: FieldType }> = {
  'artifact': { fields: ['content'], type: 'string' },
  'autonomous-system': { fields: ['number'], type: 'number' },
  'directory': { fields: ['path'], type: 'string' },
  'domain-name': { fields: ['value'], type: 'string' },
  'email-address': { fields: ['value'], type: 'string' },
  'email-message': { fields: ['subject', 'from_ref', 'to_refs'], type: 'string' },
  'file': { fields: ['hashes.MD5', 'hashes.SHA-1', 'hashes.SHA-256'], type: 'string' },
  'ipv4-addr': { fields: ['value'], type: 'string' },
  'ipv6-addr': { fields: ['value'], type: 'string' },
  'mac-address': { fields: ['value'], type: 'string' },
  'mutex': { fields: ['name'], type: 'string' },
  'network-traffic': { fields: ['src_ref', 'dst_ref'], type: 'string' },
  'process': { fields: ['pid', 'command_line'], type: 'number' },
  'software': { fields: ['name'], type: 'string' },
  'url': { fields: ['value'], type: 'string' },
  'user-account': { fields: ['account_login'], type: 'string' },
  'windows-registry-key': { fields: ['key'], type: 'string' },
  'x509-certificate': { fields: ['serial_number'], type: 'string' },
  'attack-pattern': { fields: ['name'], type: 'string' },
  'campaign': { fields: ['name'], type: 'string' },
  'course-of-action': { fields: ['name'], type: 'string' },
  'grouping': { fields: ['name'], type: 'string' },
  'identity': { fields: ['name'], type: 'string' },
  'incident': { fields: ['name'], type: 'string' },
  'indicator': { fields: ['pattern'], type: 'string' },
  'infrastructure': { fields: ['name'], type: 'string' },
  'intrusion-set': { fields: ['name'], type: 'string' },
  'location': { fields: ['name'], type: 'string' },
  'malware': { fields: ['name'], type: 'string' },
  'malware-analysis': { fields: ['product'], type: 'string' },
  'note': { fields: ['content'], type: 'string' },
  'observed-data': { fields: ['object_refs'], type: 'string' },
  'opinion': { fields: ['opinion'], type: 'string' },
  'report': { fields: ['name'], type: 'string' },
  'threat-actor': { fields: ['name'], type: 'string' },
  'tool': { fields: ['name'], type: 'string' },
  'vulnerability': { fields: ['name'], type: 'string' },
  'sighting': { fields: ['summary'], type: 'boolean' },
};

@Injectable()
export class LookupService {
  private readonly logger = new Logger(LookupService.name);
  private readonly openSearchClient: Client;
  private readonly redisClient: RedisClientType;
  private readonly debugLogging: boolean = process.env.DEBUG_LOGGING === 'true';
  private readonly cacheTtl = 3600; // 1 hour

  constructor(private readonly configService: ConfigService) {
    this.openSearchClient = new Client({
      node: this.configService.get<string>('OPENSEARCH_NODE', 'http://localhost:9200'),
      auth: {
        username: this.configService.get<string>('OPENSEARCH_USERNAME', 'admin'),
        password: this.configService.get<string>('OPENSEARCH_PASSWORD', 'admin'),
      },
    });
    this.redisClient = createClient({
      url: this.configService.get<string>('REDIS_URL', 'redis://localhost:6379'),
    });
    this.redisClient.on('error', (err) => this.logger.error(`Redis error`, { error: err.message }));
    this.redisClient.connect().catch((err) => this.logger.error(`Redis connection failed`, { error: err.message }));
  }

  private isCompatible(value: string, type: FieldType): boolean {
    if (!value || value.trim() === '') return false;
    if (type === 'string') return true;
    if (type === 'number') return !isNaN(Number(value)) && value.trim() !== '';
    if (type === 'boolean') return value.toLowerCase() === 'true' || value.toLowerCase() === 'false';
    return false;
  }

  private async getFromCache<T>(key: string): Promise<T | null> {
    try {
      const cached = await this.redisClient.get(key);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      this.logger.warn(`Failed to get cache for key "${key}"`, { error: error instanceof Error ? error.message : error });
      return null;
    }
  }

  private async setCache(key: string, value: any, ttl: number): Promise<void> {
    try {
      await this.redisClient.setEx(key, ttl, JSON.stringify(value));
    } catch (error) {
      this.logger.warn(`Failed to set cache for key "${key}"`, { error: error instanceof Error ? error.message : error });
    }
  }

  async findByValue(value: string, type?: string): Promise<any | null> {
    if (!value || value.trim() === '') {
      this.logger.warn(`Skipping search due to empty or invalid value`, { value });
      return null;
    }

    const cacheKey = `lookup:${type || 'all'}:${value}`;
    const cached = await this.getFromCache<any>(cacheKey);
    if (cached) {
      if (this.debugLogging) {
        this.logger.debug(`Cache hit for "${value}"`, { value, type, cacheKey });
      }
      return cached.result || null;
    }

    try {
      const indexesToSearch = type && STIX_INDEXES[type] ? [STIX_INDEXES[type]] : Object.values(STIX_INDEXES);
      const context = { value, type, indexes: indexesToSearch.length };
      const startTime = Date.now();

      if (this.debugLogging) {
        this.logger.debug(`Searching ${indexesToSearch.length} indexes`, context);
      }

      const searchPromises = indexesToSearch.map(async (index) => {
        const stixType = Object.keys(STIX_INDEXES).find((key) => STIX_INDEXES[key] === index);
        const fieldConfig = stixType
          ? SEARCH_FIELDS[stixType]
          : { fields: ['value', 'pattern'], type: 'string' as const };

        const compatibleFields = fieldConfig.fields.filter((field) => {
          if (field === 'command_line' && stixType === 'process') return true;
          return this.isCompatible(value, fieldConfig.type);
        });

        if (compatibleFields.length === 0) {
          if (this.debugLogging) {
            this.logger.debug(`Skipping index "${index}": no compatible fields`, {
              value,
              index,
              fieldType: fieldConfig.type,
            });
          }
          return null;
        }

        try {
          const result = await this.openSearchClient.search({
            index,
            body: {
              query: {
                bool: {
                  should: compatibleFields.map((field) => ({
                    term: { [field]: value }, // Use term for exact matches
                  })),
                  minimum_should_match: 1,
                },
              },
              size: 10, // Limit to 10 hits to avoid excessive results
            },
          });

          const hits = result.body.hits.hits;
          if (hits.length > 0 && hits[0]._source) {
            if (this.debugLogging) {
              this.logger.debug(`Hit in index "${index}"`, { value, index, matchId: hits[0]._id });
            }
            return { index, source: hits[0]._source, id: hits[0]._id };
          }
          return null;
        } catch (error) {
          this.logger.warn(`Failed to search index "${index}"`, {
            value,
            index,
            error: error instanceof Error ? error.message : error,
          });
          return null;
        }
      });

      const results = await Promise.all(searchPromises);
      const matches = results.filter((result) => result !== null && result.source) as {
        index: string;
        source: any;
        id: string;
      }[];

      const queryTime = Date.now() - startTime;
      if (this.debugLogging) {
        this.logger.debug(
          `Search completed: ${matches.length} matches in ${indexesToSearch.length} indexes (${queryTime}ms)`,
          { ...context, matches: matches.length, queryTime },
        );
      }

      // Deduplicate matches by id
      const uniqueMatches = Array.from(
        new Map(matches.map((match) => [match.source.id, match])).values(),
      );

      const found = uniqueMatches[0];
      if (found) {
        this.logger.log(`Found match for "${value}" in index "${found.index}"`, {
          value,
          index: found.index,
          matchId: found.id,
          match: {
            id: found.source.id,
            pattern: found.source.pattern,
            type: found.source.type,
          },
        });
        await this.setCache(cacheKey, { result: found.source }, this.cacheTtl);
        return found.source;
      }

      if (this.debugLogging) {
        this.logger.debug(`No valid matches found for "${value}"`, context);
      }
      await this.setCache(cacheKey, { result: null }, this.cacheTtl);
      return null;
    } catch (error) {
      this.logger.error(`Search failed for "${value}"`, {
        value,
        type,
        error: error instanceof Error ? error.message : error,
      });
      throw error;
    }
  }

  async onModuleDestroy() {
    await this.redisClient.quit();
  }
}