import { Injectable, Logger, OnModuleInit, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosError, AxiosRequestConfig } from 'axios';
import Bottleneck from 'bottleneck';
import { createClient } from 'redis';
import { GenericStixObject, EnrichmentData } from '../ingestion-from-api-feeds/feeds/feed.types';
import { TYPE_PATTERNS } from '../ingestion-from-api-feeds/feeds/feed.constants';
import { parse } from 'tldts';
import { isPrivate } from 'ip';
import { EventEmitter2 } from '@nestjs/event-emitter';
import * as Joi from 'joi';
import { EnrichmentConfig, EnrichmentTaskConfig } from 'config/enrichment-config.interface';
import { enrichmentConfig as staticEnrichmentConfig, conciseResponseFields } from 'config/enrichment.config';

interface EnrichmentOptions {
  services?: (keyof EnrichmentData)[];
}

interface EnrichmentTask {
  service: string;
  fetchFn: (value: string) => Promise<any>;
  field: keyof EnrichmentData;
  validator?: (value: string) => boolean;
  schema?: Joi.ObjectSchema;
  priority?: number;
}

@Injectable()
export class EnrichmentService implements OnModuleInit {
  private readonly logger = new Logger(EnrichmentService.name);
  private readonly debugLogging: boolean = process.env.DEBUG_LOGGING === 'true';
  private readonly apiKeys: Map<string, string> = new Map();
  private readonly limiters: Map<string, Bottleneck> = new Map();
  private redisClient: ReturnType<typeof createClient>;
  private readonly defaultCacheTtl = 3600; // 1 hour
  private readonly defaultTimeout = 20000;
  private readonly defaultMaxRetries = 3;

  private readonly fetchFunctions: Record<string, (value: string) => Promise<any>> = {
    fetchWhoisData: this.fetchWhoisData.bind(this),
    fetchGeoData: this.fetchGeoData.bind(this),
    fetchVirusTotalData: this.fetchVirusTotalData.bind(this),
    fetchVirusTotalIpData: this.fetchVirusTotalIpData.bind(this),
    fetchVirusTotalDomainData: this.fetchVirusTotalDomainData.bind(this),
    fetchVirusTotalUrlData: this.fetchVirusTotalUrlData.bind(this),
    fetchAbuseIPDBData: this.fetchAbuseIPDBData.bind(this),
    fetchShodanData: this.fetchShodanData.bind(this),
    fetchThreatFoxData: this.fetchThreatFoxData.bind(this),
    fetchDNSData: this.fetchDNSData.bind(this),
    fetchDNSDataFromUrl: this.fetchDNSDataFromUrl.bind(this),
    fetchSSLData: this.fetchSSLData.bind(this),
    fetchASNData: this.fetchASNData.bind(this),
    fetchASNDataFromNumber: this.fetchASNDataFromNumber.bind(this),
    fetchHybridAnalysisData: this.fetchHybridAnalysisData.bind(this),
    fetchThreatCrowdMutexData: this.fetchThreatCrowdMutexData.bind(this),
    fetchMispData: this.fetchMispData.bind(this),
  };

  private readonly validationSchemas: Record<string, Joi.ObjectSchema> = {
    geo: Joi.object({
      country_name: Joi.string().required(),
      country_code: Joi.string().required(),
      city: Joi.string().required(),
      lat: Joi.number().required(),
      lon: Joi.number().required(),
    }),
    whois: Joi.object({
      domainName: Joi.string().required(),
      registrarName: Joi.string().required(),
      createdDate: Joi.string().isoDate().required(),
      expiresDate: Joi.string().isoDate().required(),
    }),
    virustotal: Joi.object({
      data: Joi.object({
        attributes: Joi.object({
          last_analysis_stats: Joi.object({
            malicious: Joi.number().required(),
            undetected: Joi.number().required(),
            harmless: Joi.number().required(),
            suspicious: Joi.number().required(),
          }).required(),
          reputation: Joi.number().required(),
        }).required(),
      }).required(),
    }),
    abuseipdb: Joi.object({
      data: Joi.object({
        abuseConfidenceScore: Joi.number().required(),
        countryCode: Joi.string().required(),
        totalReports: Joi.number().required(),
      }).required(),
    }),
    shodan: Joi.object({
      ip: Joi.string().required(),
      org: Joi.string().required(),
      os: Joi.string().allow(null).required(),
    }),
    threatfox: Joi.object({
      query_status: Joi.string().required(),
      data: Joi.object({
        threat_type: Joi.string().allow('').required(),
        malware: Joi.string().allow('').required(),
      }).required(),
    }).unknown(true),
    dns: Joi.object({
      Status: Joi.number().required(),
      Answer: Joi.array().items(
        Joi.object({
          data: Joi.string().required(),
          type: Joi.string().required(),
          TTL: Joi.number().required(),
        })
      ).required(), // Enforce array, inherently allows empty arrays
    }).unknown(true),
    ssl: Joi.object({
      host: Joi.string().required(),
      endpoints: Joi.array().items(
        Joi.object({
          serverName: Joi.string().required(),
          grade: Joi.string().optional(), 
        }),
      ).required(),
    }).unknown(true),
    asn: Joi.object({
      asn: Joi.string().required(),
      org: Joi.string().required(),
      ip: Joi.string().optional(),
    }),
    hybrid: Joi.object({
      result: Joi.object({
        verdict: Joi.string().required(),
        threat_score: Joi.number().required(),
        submissions: Joi.number().required(),
      }).required(),
    }),
    threatcrowd: Joi.object({
      response_code: Joi.string().required(),
      hashes: Joi.array().items(Joi.string()).required(),
      domains: Joi.array().items(Joi.string()).required(),
    }),
    misp: Joi.object({
      response: Joi.object({
        Attribute: Joi.array().items(
          Joi.object({
            value: Joi.string().required(),
            type: Joi.string().required(),
            category: Joi.string().required(),
          }),
        ).required(),
      }).required(),
    }),
  };

  constructor(
    private readonly configService: ConfigService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async onModuleInit() {
    await this.initializeRedis();
    await this.initializeApiServices();
  }


  
  private async initializeRedis() {
    this.redisClient = createClient({
      url: this.configService.get<string>('REDIS_URL'),
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 5) {
            this.logger.error('Redis connection failed after 5 retries', { retries });
            return new Error('Max retries reached');
          }
          return Math.min(retries * 100, 5000);
        },
      },
    });

    this.redisClient.on('error', (err) => {
      this.logger.error('Redis error', { error: err.message });
    });

    await this.redisClient.connect();
  }

  private async initializeApiServices() {
    const enrichmentConfig = this.configService.get<EnrichmentConfig>('enrichmentConfig') || staticEnrichmentConfig;
    for (const [service, config] of Object.entries(enrichmentConfig.apiConfigs)) {
      const apiKey = process.env[config.apiKeyEnv || ''];
      if (config.apiKeyEnv) {
        if (apiKey) {
          this.apiKeys.set(service, apiKey);
          this.logger.log(`API key loaded for ${service}`, { service, apiKey: '[set]' });
        } else if (config.requiredKey) {
          this.logger.warn(`API key missing for ${service} (required)`, { service });
        } else {
          this.logger.log(`API key not set for ${service} (optional)`, { service });
        }
      }
      if (config.rateLimit) {
        this.limiters.set(
          service,
          new Bottleneck({
            maxConcurrent: 1,
            minTime: config.rateLimit.perMilliseconds / config.rateLimit.maxRequests,
          }),
        );
      }
    }
  }

  private normalizeType(type: string): string {
    const typeMap: Record<string, string> = {
      filemd5: 'file',
      filesha1: 'file',
      filesha256: 'file',
      filesha512: 'file',
      'filehash-md5': 'file',
      'filehash-sha1': 'file',
      'filehash-sha256': 'file',
      'filehash-sha512': 'file',
      email: 'email-addr',
      hostname: 'domain-name',
      ipv4: 'ipv4-addr',
      ipv6: 'ipv6-addr',
      domain: 'domain-name',
      yara: 'indicator',
    };
    return typeMap[type.toLowerCase()] || type.toLowerCase().replace('filehash-', 'file');
  }

  private filterConciseResponse(service: string, data: any): any {
    const fields = conciseResponseFields[service] || [];
    if (!fields.length) {
      return data;
    }

    const result: any = {};
    for (const field of fields) {
      const fieldParts = field.split('.');
      let value = data;
      let target = result;

      for (let i = 0; i < fieldParts.length; i++) {
        const part = fieldParts[i];
        if (i === fieldParts.length - 1) {
          if (value && value[part] !== undefined) {
            target[part] = value[part];
          }
        } else {
          value = value ? value[part] : undefined;
          target[part] = target[part] || {};
          target = target[part];
        }
      }
    }

    return Object.keys(result).length > 0 ? result : data;
  }

  async enrichIndicator(
    indicator: GenericStixObject,
    options: EnrichmentOptions = {},
  ): Promise<GenericStixObject & { enrichment: Partial<EnrichmentData> }> {
    const primaryValue = this.getPrimaryValue(indicator);
    const cacheKey = `enrich:${indicator.type}:${primaryValue}`;
    const context = {
      value: primaryValue,
      type: indicator.type,
      sourceConfigId: indicator.sourceConfigId,
    };

    try {
      const cached = await this.getFromCache<EnrichmentData>(cacheKey);
      if (cached) {
        if (this.debugLogging) {
          this.logger.debug(`Cache hit for ${indicator.type}`, context);
        }
        this.eventEmitter.emit('enrichment.cache.hit', { type: indicator.type, value: primaryValue });
        const filteredCached = options.services ? this.filterEnrichmentResults(cached, options.services) : cached;
        return { ...indicator, enrichment: filteredCached };
      }

      if (this.shouldSkipEnrichment(indicator, primaryValue)) {
        await this.setCache(cacheKey, {});
        return { ...indicator, enrichment: {} };
      }

      const typeKey = this.determineTypeKey(indicator, primaryValue);
      const tasks = this.getValidTasks(typeKey, primaryValue, options.services);

      if (!tasks.length) {
        this.logger.warn(`No enrichment tasks available for ${typeKey}`, context);
        await this.setCache(cacheKey, {});
        return { ...indicator, enrichment: {} };
      }

      const enrichment = await this.executeEnrichmentTasks(tasks, primaryValue, context);
      const filteredEnrichment = options.services ? this.filterEnrichmentResults(enrichment, options.services) : enrichment;
      await this.setCache(cacheKey, filteredEnrichment);

      if (Object.keys(filteredEnrichment).length > 0) {
        this.logger.log(`Enriched ${indicator.type}: ${Object.keys(filteredEnrichment).length} services`, {
          ...context,
          services: Object.keys(filteredEnrichment),
        });
        this.eventEmitter.emit('enrichment.completed', {
          type: indicator.type,
          value: primaryValue,
          services: Object.keys(filteredEnrichment),
        });
      } else if (this.debugLogging) {
        this.logger.debug(`No enrichment data for ${indicator.type}`, context);
      }

      return { ...indicator, enrichment: filteredEnrichment };
    } catch (error) {
      this.logger.error(`Failed to enrich ${indicator.type}`, { ...context, error: error instanceof Error ? error.message : error });
      this.eventEmitter.emit('enrichment.failed', {
        type: indicator.type,
        value: primaryValue,
        error: error instanceof Error ? error.message : error,
      });
      return { ...indicator, enrichment: {} };
    }
  }

  private filterEnrichmentResults(
    enrichment: EnrichmentData,
    services: (keyof EnrichmentData)[],
  ): Partial<EnrichmentData> {
    const filtered: Partial<EnrichmentData> = {};
    for (const service of services) {
      if (enrichment[service] !== undefined) {
        // Explicitly assign to the correct field with type safety
        (filtered as Record<keyof EnrichmentData, EnrichmentData[keyof EnrichmentData]>)[service] = enrichment[service];
      }
    }
    return filtered;
  }
  private getPrimaryValue(indicator: GenericStixObject): string {
    if (indicator.type === 'file' || this.normalizeType(indicator.type) === 'file') {
      return (
        indicator.hashes?.['SHA-256'] ||
        indicator.hashes?.['SHA-1'] ||
        indicator.hashes?.['MD5'] ||
        indicator.hashes?.['SHA-512'] ||
        Object.values(indicator.hashes || {})[0] ||
        indicator.indicator ||
        indicator.value ||
        indicator.name ||
        ''
      );
    }
    return indicator.indicator || indicator.value || indicator.name || Object.values(indicator.hashes || {})[0] || '';
  }

  private shouldSkipEnrichment(indicator: GenericStixObject, value: string): boolean {
    try {
      if (indicator.type === 'ipv4-addr' || indicator.type === 'ipv6-addr') {
        const isValidIP = indicator.type === 'ipv4-addr'
          ? TYPE_PATTERNS['ipv4-addr'].test(value)
          : TYPE_PATTERNS['ipv6-addr'].test(value);
        
        if (!isValidIP) {
          this.logger.warn(`Invalid IP format for ${indicator.type}`, {
            id: indicator.id,
            type: indicator.type,
            value,
            sourceConfigId: indicator.sourceConfigId,
          });
          return true;
        }

        if (isPrivate(value)) {
          if (this.debugLogging) {
            this.logger.debug(`Skipping private IP for ${indicator.type}`, {
              id: indicator.id,
              type: indicator.type,
              value,
              sourceConfigId: indicator.sourceConfigId,
            });
          }
          return true;
        }
      }
      
      if (indicator.type === 'domain-name' && ['localhost', '127.0.0.1'].includes(value.toLowerCase())) {
        return true;
      }
      
      if (!value) {
        this.logger.warn(`No value for ${indicator.type}`, {
          id: indicator.id,
          type: indicator.type,
          sourceConfigId: indicator.sourceConfigId,
        });
        return true;
      }
      
      return false;
    } catch (error) {
      this.logger.error(`Error checking if enrichment should be skipped for ${indicator.type}`, {
        id: indicator.id,
        type: indicator.type,
        value,
        sourceConfigId: indicator.sourceConfigId,
        error: error instanceof Error ? error.message : error,
      });
      return true;
    }
  }

  private determineTypeKey(indicator: GenericStixObject, primaryValue: string): string {
    let typeKey = this.normalizeType(indicator.type);
    if (typeKey === 'file' && TYPE_PATTERNS['url'].test(primaryValue)) {
      typeKey = 'url';
    }
    return typeKey;
  }

  private getValidTasks(
    typeKey: string,
    primaryValue: string,
    services?: (keyof EnrichmentData)[],
  ): EnrichmentTask[] {
    const config = this.configService.get<EnrichmentConfig>('enrichmentConfig') || staticEnrichmentConfig;
    let tasksConfig = config.enrichmentRegistry[typeKey] || [];

    if (services && services.length > 0) {
      tasksConfig = tasksConfig.filter((task: EnrichmentTaskConfig) => services.includes(task.field as keyof EnrichmentData));
    }

    return tasksConfig
      .filter((task: EnrichmentTaskConfig) => {
        if (config.apiConfigs[task.service]?.requiredKey && !this.apiKeys.has(task.service)) {
          return false;
        }
        if (task.validator) {
          const validatorFn = this.getValidator(task.validator);
          if (!validatorFn(primaryValue)) {
            return false;
          }
        }
        return true;
      })
      .map((task: EnrichmentTaskConfig) => ({
        service: task.service,
        fetchFn: this.fetchFunctions[task.fetchFn] || (() => Promise.reject(new Error(`Unknown fetch function: ${task.fetchFn}`))),
        field: task.field as keyof EnrichmentData,
        validator: task.validator ? this.getValidator(task.validator) : undefined,
        schema: this.validationSchemas[task.service] || undefined,
        priority: task.priority,
      }))
      .sort((a, b) => (b.priority || 0) - (a.priority || 0));
  }

  private getValidator(validator: string): (value: string) => boolean {
    if (validator in TYPE_PATTERNS) {
      return TYPE_PATTERNS[validator].test.bind(TYPE_PATTERNS[validator]);
    }
    try {
      const regex = new RegExp(validator);
      return (value: string) => regex.test(value);
    } catch {
      this.logger.warn(`Invalid validator regex: ${validator}`, { validator });
      return () => true;
    }
  }

  private async executeEnrichmentTasks(tasks: EnrichmentTask[], primaryValue: string, context: { value: string; type: string; sourceConfigId?: string }): Promise<EnrichmentData> {
    const results = await Promise.allSettled(
      tasks.map((task) => this.executeSingleTask(task, primaryValue, context)),
    );

    const enrichment: EnrichmentData = {};
    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        enrichment[tasks[index].field] = result.value;
      } else if (result.status === 'rejected' && this.debugLogging) {
        this.logger.debug(`Task failed for ${tasks[index].service}`, {
          ...context,
          service: tasks[index].service,
          error: result.reason instanceof Error ? result.reason.message : result.reason,
        });
      }
    });
    return enrichment;
  }

  private async executeSingleTask(
    task: EnrichmentTask,
    value: string,
    context: { value: string; type: string; sourceConfigId?: string },
  ): Promise<any> {
    const taskCacheKey = `task:${task.service}:${value}`;
    try {
      const cached = await this.getFromCache(taskCacheKey);
      if (cached) {
        if (this.debugLogging) {
          this.logger.debug(`Task cache hit for ${task.service}`, { ...context, service: task.service });
        }
        return cached;
      }

      const limiter = this.limiters.get(task.service);
      if (!limiter) {
        throw new Error(`No rate limiter for ${task.service}`);
      }

      const result = await limiter.schedule(() => task.fetchFn.call(this, value));

      if (result) {
        const validatedResult = task.schema
          ? this.validateAndNormalizeResponse(result, task.schema, task.service)
          : result;

        if (validatedResult) {
          const conciseResult = this.filterConciseResponse(task.service, validatedResult);
          await this.setCache(taskCacheKey, conciseResult, this.getCacheTtlForService(task.service));
          return conciseResult;
        }
      }
      return null;
    } catch (error) {
      this.handleTaskError(task.service, value, error, context);
      return null;
    }
  }

  private validateAndNormalizeResponse(data: any, schema: Joi.ObjectSchema, service: string): any {
    const { error, value } = schema.validate(data, { stripUnknown: true });
    if (error) {
      this.logger.warn(`Response validation failed for ${service}`, {
        error: error.message,
        response: JSON.stringify(data, null, 2),
        service,
      });
      return null;
    }
    return value;
  }
  private getCacheTtlForService(service: string): number {
    switch (service) {
      case 'geo':
        return 86400;
      case 'whois':
        return 604800;
      case 'dns':
        return 43200;
      default:
        return this.defaultCacheTtl;
    }
  }

  private async getFromCache<T>(key: string): Promise<T | null> {
    try {
      const cached = await this.redisClient.get(key);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      this.logger.error(`Cache read error`, { key, error: error instanceof Error ? error.message : error });
      return null;
    }
  }

  private async setCache(key: string, value: any, ttl?: number): Promise<void> {
    try {
      await this.redisClient.set(
        key,
        JSON.stringify(value),
        { EX: ttl || this.defaultCacheTtl },
      );
    } catch (error) {
      this.logger.error(`Cache write error`, { key, error: error instanceof Error ? error.message : error });
    }
  }

  private handleTaskError(service: string, value: string, error: any, context: { value: string; type: string; sourceConfigId?: string }): void {
    const axiosError = error as AxiosError;
    const status = axiosError.response?.status;
    let errorMessage: string;
    if (status) {
      errorMessage = `API error (${status}): ${axiosError.message}`;
    } else if (axiosError.code === 'ECONNABORTED') {
      errorMessage = `Network error: Timed out after ${axiosError.config?.timeout || this.defaultTimeout}ms`;
    } else {
      errorMessage = `Network error: ${axiosError.message}`;
    }

    this.logger.error(`Enrichment failed for ${service}`, {
      ...context,
      service,
      error: errorMessage,
    });

    this.eventEmitter.emit('enrichment.error', {
      service,
      value,
      error: errorMessage,
    });
  }

  private interpolateHeaders(headers: Record<string, string>, apiKey: string): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      result[key] = value.replace('${apiKey}', apiKey);
    }
    return result;
  }

  async fetchApi(
    service: string,
    endpoint: string,
    config: AxiosRequestConfig = {},
    retryCount = 0,
  ): Promise<any> {
    const enrichmentConfig = this.configService.get<EnrichmentConfig>('enrichmentConfig') || staticEnrichmentConfig;
    const apiConfig = enrichmentConfig.apiConfigs[service];
    if (!apiConfig) {
      throw new Error(`Unknown service: ${service}`);
    }
  
    const apiKey = this.apiKeys.get(service);
    if (apiConfig.requiredKey && !apiKey) {
      this.logger.warn(`Skipping ${service} enrichment: API key is missing`, { service });
      throw new Error(`Missing ${service} API key`);
    }
  
    const baseUrl = config.baseURL || apiConfig.url.replace(/\/$/, '');
    const url = endpoint ? `${baseUrl}/${endpoint.replace(/^\//, '')}` : baseUrl;
  
    const headers = {
      ...this.interpolateHeaders(apiConfig.headers || {}, apiKey || ''),
      ...(config.headers || {}),
      'User-Agent': 'CyberThreatIntelPlatform/1.0',
    };
  
    const params = {
      ...Object.fromEntries(
        Object.entries(apiConfig.params || {}).map(([k, v]) => [
          k,
          typeof v === 'string' ? v.replace('${apiKey}', apiKey || '') : v,
        ]),
      ),
      ...(config.params || {}),
    };
  
    // Ensure config.data is preserved
    const data = config.data !== undefined ? config.data : apiConfig.data;
    const requestConfig: AxiosRequestConfig = {
      method: config.method || apiConfig.method || 'get',
      url,
      headers,
      params,
      data: data ? (typeof data === 'string' ? data : JSON.stringify(data)) : undefined,
      timeout: apiConfig.timeout || this.defaultTimeout,
    };
  
    if (this.debugLogging) {
      this.logger.debug(`Fetching API for ${service}`, {
        service,
        baseURL: baseUrl,
        url: requestConfig.url,
        method: requestConfig.method,
        headers: { ...requestConfig.headers, 'x-apikey': '[redacted]' },
        params: requestConfig.params,
        data: requestConfig.data || 'none',
      });
    }
  
    try {
      const response = await axios(requestConfig);
      if (this.debugLogging && service === 'virustotal') {
        this.logger.debug(`VirusTotal API response`, {
          service,
          baseURL: baseUrl,
          url: requestConfig.url,
          status: response.status,
          data: JSON.stringify(response.data, null, 2).substring(0, 500),
        });
      }
      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      if (axiosError.response?.status === 403) {
        this.logger.error(`Invalid API credentials for ${service}`, {
          service,
          baseURL: baseUrl,
          error: JSON.stringify(axiosError.response?.data || axiosError.message, null, 2).substring(0, 500),
        });
        throw new InternalServerErrorException(`Invalid ${service} API credentials`);
      }
      if (service === 'virustotal' && axiosError.response?.status === 404) {
        this.logger.warn(`VirusTotal resource not found`, {
          service,
          baseURL: baseUrl,
          url: requestConfig.url,
          error: JSON.stringify(axiosError.response?.data || axiosError.message, null, 2).substring(0, 500),
        });
        return null;
      }
  
      const maxRetries = apiConfig.retryPolicy?.maxRetries || this.defaultMaxRetries;
      if (
        ([429, 502, 503].includes(axiosError.response?.status || 0) ||
          ['ECONNREFUSED', 'ETIMEDOUT'].includes(axiosError.code || '')) &&
        retryCount < maxRetries
      ) {
        const delay = Math.pow(2, retryCount) * (apiConfig.retryPolicy?.baseDelay || 1000);
        if (this.debugLogging) {
          this.logger.debug(`Retrying ${service} after ${delay}ms`, {
            service,
            baseURL: baseUrl,
            endpoint,
            retryCount: retryCount + 1,
          });
        }
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.fetchApi(service, endpoint, config, retryCount + 1);
      }
  
      const message = axiosError.response?.data
        ? JSON.stringify(axiosError.response.data, null, 2)
        : axiosError.message;
      this.logger.error(`API failed for ${service} after ${retryCount + 1} attempts`, {
        service,
        baseURL: baseUrl,
        url: requestConfig.url,
        error: message.substring(0, 500),
      });
      throw axiosError;
    }
  }
  async fetchWhoisData(domain: string): Promise<any> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }
    const response = await this.fetchApi('whois', '', { params: { domainName: domain } });
    if (!response || !response.WhoisRecord) {
      throw new Error(response?.ErrorMessage?.msg || 'Invalid WHOIS response');
    }
    return {
      domainName: response.WhoisRecord.domainName,
      registrarName: response.WhoisRecord.registrarName,
      createdDate: response.WhoisRecord.createdDate,
      expiresDate: response.WhoisRecord.expiresDate,
    };
  }

  async fetchGeoData(ip: string): Promise<any> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }
    const response = await this.fetchApi('geo', `/${ip}`, {
      params: { fields: 'country,countryCode,city,lat,lon' },
    });
    if (!response || !response.country) {
      throw new Error('Invalid GeoIP response');
    }
    return {
      country_name: response.country,
      country_code: response.countryCode,
      city: response.city,
      lat: response.lat,
      lon: response.lon,
    };
  }

  async fetchVirusTotalData(hash: string): Promise<any> {
    if (!/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash)) {
      throw new Error(`Invalid hash format: ${hash}`);
    }
    const context = { service: 'virustotal', hash };
    const cacheKey = `task:virustotal:${hash}`;
    if (this.debugLogging) {
      this.logger.debug(`Fetching VirusTotal file data`, { ...context });
    }
    try {
      const cached = await this.getFromCache<any>(cacheKey);
      if (cached) {
        if (this.debugLogging) {
          this.logger.debug(`Cache hit for VirusTotal file data`, {
            ...context,
            cacheKey,
            response: JSON.stringify(cached, null, 2).substring(0, 500),
          });
        }
        return cached;
      }
  
      const response = await this.fetchApi('virustotal', `/files/${hash}`);
      if (!response || !response.data) {
        this.logger.warn(`Invalid VirusTotal file response`, {
          ...context,
          response: JSON.stringify(response, null, 2).substring(0, 500),
        });
        const defaultResponse = {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, undetected: 0, harmless: 0, suspicious: 0 },
              reputation: 0,
            },
          },
        };
        await this.setCache(cacheKey, defaultResponse, 3600);
        return defaultResponse;
      }
  
      const result = {
        data: {
          attributes: {
            last_analysis_stats: response.data.attributes.last_analysis_stats,
            reputation: response.data.attributes.reputation || 0,
          },
        },
      };
      await this.setCache(cacheKey, result, 86400);
      return result;
    } catch (error) {
      const axiosError = error as AxiosError;
      if (axiosError.response?.status === 404) {
        this.logger.warn(`File not found in VirusTotal`, {
          ...context,
          error: JSON.stringify(axiosError.response?.data || axiosError.message, null, 2).substring(0, 500),
        });
        const defaultResponse = {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, undetected: 0, harmless: 0, suspicious: 0 },
              reputation: 0,
            },
          },
        };
        await this.setCache(cacheKey, defaultResponse, 3600);
        return defaultResponse;
      }
      this.logger.error(`VirusTotal file request failed`, {
        ...context,
        error: JSON.stringify(axiosError.response?.data || axiosError.message, null, 2).substring(0, 500),
      });
      throw error;
    }
  }
  async fetchVirusTotalIpData(ip: string): Promise<any> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }
    const response = await this.fetchApi('virustotal', `/ip_addresses/${ip}`);
    if (!response || !response.data) {
      throw new Error('Invalid VirusTotal response');
    }
    return {
      data: {
        attributes: {
          last_analysis_stats: response.data.attributes.last_analysis_stats,
          reputation: response.data.attributes.reputation || 0,
        },
      },
    };
  }

  async fetchVirusTotalDomainData(domain: string): Promise<any> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }
    const response = await this.fetchApi('virustotal', `/domains/${domain}`);
    if (!response || !response.data) {
      throw new Error('Invalid VirusTotal response');
    }
    return {
      data: {
        attributes: {
          last_analysis_stats: response.data.attributes.last_analysis_stats,
          reputation: response.data.attributes.reputation || 0,
        },
      },
    };
  }

 

  async fetchVirusTotalUrlData(url: string): Promise<any> {
    if (!TYPE_PATTERNS['url'].test(url)) {
      throw new Error(`Invalid URL format: ${url}`);
    }
    const context = { service: 'virustotal', url };
    const apiKey = this.apiKeys.get('virustotal');
    if (!apiKey) {
      this.logger.warn(`Skipping VirusTotal URL enrichment: API key missing`, context);
      return {
        data: {
          attributes: {
            last_analysis_stats: { malicious: 0, undetected: 0, harmless: 0, suspicious: 0 },
            reputation: 0,
          },
        },
      };
    }
  
    try {
      let encodedUrl: string;
      try {
        encodedUrl = encodeURIComponent(url);
      } catch (error) {
        this.logger.warn(`Failed to encode URL for VirusTotal`, {
          ...context,
          error: error instanceof Error ? error.message : error,
        });
        return {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, undetected: 0, harmless: 0, suspicious: 0 },
              reputation: 0,
            },
          },
        };
      }
  
      const payload = { url: encodedUrl };
      const requestConfig: AxiosRequestConfig = {
        method: 'post',
        url: 'https://www.virustotal.com/api/v3/urls',
        headers: {
          'Content-Type': 'application/json',
          'x-apikey': apiKey,
          'User-Agent': 'CyberThreatIntelPlatform/1.0',
        },
        data: JSON.stringify(payload), // Explicit JSON serialization
        timeout: 30000,
      };
  
      if (this.debugLogging) {
        this.logger.debug(`Sending VirusTotal URL request`, {
          ...context,
          requestConfig: {
            url: requestConfig.url,
            method: requestConfig.method,
            headers: { ...requestConfig.headers, 'x-apikey': '[redacted]' },
            data: requestConfig.data,
          },
        });
      }
  
      const initialResponse = await axios(requestConfig).then((res) => res.data).catch((error) => {
        throw error;
      });
  
      if (!initialResponse?.data?.id) {
        this.logger.warn(`Invalid VirusTotal URL response`, {
          ...context,
          response: JSON.stringify(initialResponse, null, 2).substring(0, 500),
        });
        return {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, undetected: 0, harmless: 0, suspicious: 0 },
              reputation: 0,
            },
          },
        };
      }
  
      const analysisId = initialResponse.data.id;
      const maxAttempts = 3;
      const delayMs = 5000;
      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        try {
          const response = await this.fetchApi('virustotal', `/analyses/${analysisId}`);
          if (!response?.data) {
            this.logger.warn(`Invalid VirusTotal analysis response`, {
              ...context,
              analysisId,
              attempt: attempt + 1,
              response: JSON.stringify(response, null, 2).substring(0, 500),
            });
            continue;
          }
          if (response.data.attributes?.status === 'completed') {
            if (this.debugLogging) {
              this.logger.debug(`VirusTotal URL analysis succeeded`, {
                ...context,
                attempt: attempt + 1,
                analysisId,
              });
            }
            return {
              data: {
                attributes: {
                  last_analysis_stats: response.data.attributes.stats || {
                    malicious: 0,
                    undetected: 0,
                    harmless: 0,
                    suspicious: 0,
                  },
                  reputation: 0,
                },
              },
            };
          }
        } catch (error) {
          this.logger.debug(`VirusTotal analysis poll attempt ${attempt + 1} failed`, {
            ...context,
            attempt: attempt + 1,
            analysisId,
            error: error instanceof Error ? error.message : error,
          });
        }
      }
      this.logger.warn(`VirusTotal URL analysis timed out`, { ...context, analysisId });
      return {
        data: {
          attributes: {
            last_analysis_stats: { malicious: 0, undetected: 0, harmless: 0, suspicious: 0 },
            reputation: 0,
          },
        },
      };
    } catch (error) {
      const axiosError = error as AxiosError;
      if (axiosError.response?.status === 400) {
        this.logger.warn(`VirusTotal URL request failed with Bad Request`, {
          ...context,
          error: JSON.stringify(axiosError.response?.data || axiosError.message, null, 2).substring(0, 500),
        });
        return {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, undetected: 0, harmless: 0, suspicious: 0 },
              reputation: 0,
            },
          },
        };
      }
      this.logger.error(`VirusTotal URL request failed`, {
        ...context,
        error: JSON.stringify(axiosError.response?.data || axiosError.message, null, 2).substring(0, 500),
      });
      throw error;
    }
  }
  async fetchAbuseIPDBData(ip: string): Promise<any> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }
    const response = await this.fetchApi('abuseipdb', '', {
      params: { ipAddress: ip, maxAgeInDays: 90 },
    });
    if (!response || !response.data) {
      throw new Error('Invalid AbuseIPDB response');
    }
    return {
      data: {
        abuseConfidenceScore: response.data.abuseConfidenceScore,
        countryCode: response.data.countryCode,
        totalReports: response.data.totalReports,
      },
    };
  }

  async fetchShodanData(ip: string): Promise<any> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }
    const apiKey = this.apiKeys.get('shodan');
    if (!apiKey) {
      this.logger.warn(`Skipping Shodan enrichment for IP ${ip}: API key is missing`, { service: 'shodan' });
      throw new Error('Missing Shodan API key');
    }
    const cacheKey = `shodan:${ip}`;
    const cached = await this.getFromCache<any>(cacheKey);
    if (cached) {
      if (cached.error) {
        this.logger.warn(`Cached Shodan error for IP ${ip}`, { service: 'shodan', error: cached.error });
        throw new Error(`Cached Shodan error: ${cached.error}`);
      }
      return cached;
    }
    try {
      const response = await this.fetchApi('shodan', `/shodan/host/${ip}`);
      if (!response || !response.ip) {
        throw new Error('Invalid Shodan response');
      }
      const result = {
        ip: response.ip_str,
        org: response.org || 'Unknown',
        os: response.os || null,
      };
      await this.setCache(cacheKey, result, this.defaultCacheTtl);
      return result;
    } catch (error) {
      if (error instanceof AxiosError && error.response?.status === 403) {
        const errorMsg = error.response?.data?.error || 'Invalid or unauthorized Shodan API credentials';
        this.logger.error(`Shodan API error for IP ${ip}`, { service: 'shodan', error: errorMsg });
        await this.setCache(cacheKey, { error: errorMsg }, 3600);
        throw new Error(`Shodan API error: ${errorMsg}`);
      }
      throw error;
    }
  }

  async fetchThreatFoxData(ioc: string): Promise<any> {
    if (!ioc || typeof ioc !== 'string') {
      throw new Error('Invalid IOC value');
    }
    const context = { service: 'threatfox', ioc };
    try {
      const response = await this.fetchApi('threatfox', '/', {
        method: 'post',
        data: { query: 'search_ioc', search_term: ioc },
      });
      if (!response || !response.query_status) {
        return {
          query_status: 'no_result',
          data: {
            threat_type: '',
            malware: '',
          },
        };
      }
      return {
        query_status: response.query_status,
        data: response.data?.length > 0
          ? {
              threat_type: response.data[0].threat_type || '',
              malware: response.data[0].malware || '',
            }
          : {
              threat_type: '',
              malware: '',
            },
      };
    } catch (error) {
      this.logger.error(`ThreatFox fetch failed`, {
        ...context,
        error: error instanceof Error ? error.message : error,
      });
      return {
        query_status: 'no_result',
        data: {
          threat_type: '',
          malware: '',
        },
      };
    }
  }

  async clearCacheForDomain(domain: string): Promise<void> {
    const cacheKey = `dns:${domain}`;
    try {
      await this.redisClient.del(cacheKey);
      this.logger.debug(`Cleared DNS cache for ${domain}`, { cacheKey });
    } catch (error) {
      this.logger.error(`Failed to clear DNS cache for ${domain}`, {
        cacheKey,
        error: error instanceof Error ? error.message : error,
      });
    }
  }

  async fetchDNSData(domain: string): Promise<any> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }
    const parsed = parse(domain);
    if (!parsed.domain) {
      throw new Error(`Invalid domain: ${domain}`);
    }
    const cacheKey = `dns:${parsed.domain}`;
    const context = { service: 'dns', domain: parsed.domain };
  
    const cached = await this.getFromCache<any>(cacheKey);
    if (cached) {
      if (!cached.Answer || !Array.isArray(cached.Answer)) {
        this.logger.warn(`Invalid cached DNS data for ${parsed.domain}`, {
          ...context,
          cacheKey,
          cached: JSON.stringify(cached, null, 2).substring(0, 500),
        });
        await this.redisClient.del(cacheKey);
      } else {
        if (this.debugLogging) {
          this.logger.debug(`Cache hit for DNS data: ${parsed.domain}`, {
            ...context,
            cacheKey,
            answerCount: cached.Answer.length,
            status: cached.Status,
          });
        }
        return cached;
      }
    }
  
    const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'];
    let responses = await Promise.all(
      recordTypes.map((type) =>
        this.fetchApi('dns', '', {
          method: 'get',
          params: { name: parsed.domain, type },
          headers: { 'Accept': 'application/dns-json' },
          timeout: 30000,
        }).catch((error) => {
          this.logger.warn(`DNS query failed for ${parsed.domain} (${type})`, {
            ...context,
            error: error instanceof Error ? error.message : error,
          });
          return null;
        }),
      ),
    );
  
    let allFailed = responses.every((res) => !res || res.Status !== 0 || (!res.Answer && !res.Authority));
    if (allFailed) {
      this.logger.warn(`All DNS queries failed for ${parsed.domain}, trying Google DNS fallback`, context);
      responses = await Promise.all(
        recordTypes.map((type) =>
          this.fetchApi('dns', '', {
            method: 'get',
            params: { name: parsed.domain, type },
            headers: { 'Accept': 'application/dns-json' },
            baseURL: 'https://dns.google/resolve',
            timeout: 30000,
          }).catch((error) => {
            this.logger.warn(`Google DNS query failed for ${parsed.domain} (${type})`, {
              ...context,
              error: error instanceof Error ? error.message : error,
            });
            return null;
          }),
        ),
      );
    }
  
    allFailed = responses.every((res) => !res || res.Status !== 0 || (!res.Answer && !res.Authority));
    if (allFailed) {
      this.logger.warn(`Google DNS queries failed for ${parsed.domain}, trying Cloudflare DNS fallback`, context);
      responses = await Promise.all(
        recordTypes.map((type) =>
          this.fetchApi('dns', '', {
            method: 'get',
            params: { name: parsed.domain, type },
            headers: { 'Accept': 'application/dns-json' },
            baseURL: 'https://cloudflare-dns.com/dns-query',
            timeout: 30000,
          }).catch((error) => {
            this.logger.warn(`Cloudflare DNS query failed for ${parsed.domain} (${type})`, {
              ...context,
              error: error instanceof Error ? error.message : error,
            });
            return null;
          }),
        ),
      );
    }
  
    const typeMap: Record<number, string> = {
      1: 'A',
      5: 'CNAME',
      15: 'MX',
      2: 'NS',
      16: 'TXT',
      28: 'AAAA',
      6: 'SOA',
    };
  
    let answers: any[] = [];
    responses.forEach((res, index) => {
      if (res?.Status === 0) {
        if (Array.isArray(res?.Answer)) {
          answers.push(
            ...res.Answer.filter((answer: any) => answer?.data && typeof answer.data === 'string').map(
              (answer: any) => ({
                data: answer.data,
                type: typeMap[answer.type] || answer.type.toString(),
                TTL: answer.TTL || 0,
              }),
            ),
          );
        }
        if (Array.isArray(res?.Authority)) {
          answers.push(
            ...res.Authority.filter((auth: any) => auth?.data && typeof auth.data === 'string').map(
              (auth: any) => ({
                data: auth.data,
                type: typeMap[auth.type] || auth.type.toString(),
                TTL: auth.TTL || 0,
              }),
            ),
          );
        }
        if (!res.Answer && !res.Authority) {
          this.logger.warn(`Unexpected DNS Answer format for ${parsed.domain} (${recordTypes[index]})`, {
            ...context,
            response: JSON.stringify(res, null, 2).substring(0, 500),
          });
        }
      } else if (res) {
        this.logger.warn(`DNS query returned non-zero status for ${parsed.domain} (${recordTypes[index]})`, {
          ...context,
          status: res.Status,
          response: JSON.stringify(res, null, 2).substring(0, 500),
        });
      }
    });
  
    const result = {
      Status: answers.length > 0 ? 0 : 2,
      Answer: answers,
    };
  
    const { error } = this.validationSchemas.dns.validate(result, { stripUnknown: true });
    if (error) {
      this.logger.warn(`DNS result validation failed for ${parsed.domain}`, {
        ...context,
        error: error.message,
        result: JSON.stringify(result, null, 2).substring(0, 500),
      });
      return { Status: 2, Answer: [] };
    }
  
    await this.setCache(cacheKey, result, result.Status === 0 ? 86400 : 3600);
    if (this.debugLogging) {
      this.logger.debug(`Cached DNS data for ${parsed.domain}`, {
        ...context,
        answerCount: answers.length,
        status: result.Status,
        cacheKey,
      });
    }
    return result;
  }
  async fetchDNSDataFromUrl(url: string): Promise<any> {
    if (!TYPE_PATTERNS['url'].test(url)) {
      throw new Error(`Invalid URL format: ${url}`);
    }
    const parsed = parse(url);
    const domain = parsed.domain;
    if (!domain || !TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Could not extract valid domain from URL: ${url}`);
    }
    return this.fetchDNSData(domain);
  }

  async fetchSSLData(domain: string): Promise<any> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }
    const parsed = parse(domain);
    if (!parsed.domain || !parsed.isIcann || parsed.subdomain?.split('.').length > 2) {
      throw new Error(`Invalid or overly nested domain: ${domain}`);
    }
    const cacheKey = `ssl:${parsed.domain}`;
    const context = { value: domain, service: 'ssl' };
    const cached = await this.getFromCache<any>(cacheKey);
    if (cached) {
      return cached;
    }
    const startResponse = await this.fetchApi('ssl', '', {
      params: { host: parsed.domain, startNew: 'on', all: 'done' },
    });
    if (!startResponse || startResponse.status === 'ERROR') {
      const errorMsg = startResponse?.message || 'Failed to start SSL analysis';
      await this.setCache(cacheKey, { host: parsed.domain, status: 'ERROR' }, 3600);
      throw new Error(errorMsg);
    }
    const maxAttempts = 3;
    const delayMs = 5000;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      try {
        const result = await this.fetchApi('ssl', '', {
          params: { host: parsed.domain },
        });
        if (result.status === 'READY') {
          if (this.debugLogging) {
            this.logger.debug(`SSL analysis succeeded`, { ...context, attempt: attempt + 1 });
          }
          const formattedResult = {
            host: parsed.domain,
            endpoints: result.endpoints.map((e: any) => ({
              serverName: e.serverName || parsed.domain,
              grade: e.grade || 'N/A', // Default to 'N/A' if grade is missing
              statusMessage: e.statusMessage || 'Unknown', // Include status for debugging
            })),
          };
          await this.setCache(cacheKey, formattedResult, 86400);
          return formattedResult;
        }
        if (result.status === 'ERROR') {
          const errorMsg = result.message || 'Unknown error';
          throw new Error(`SSL analysis failed: ${errorMsg}`);
        }
      } catch (error) {
        if (attempt === maxAttempts - 1) {
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          throw new Error(`SSL analysis failed after ${maxAttempts} attempts: ${errorMsg}`);
        }
      }
    }
    throw new Error(`SSL analysis timed out after ${maxAttempts * delayMs / 1000} seconds`);
  }
  

  async fetchASNData(ip: string): Promise<any> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }
    const response = await this.fetchApi('asn', `/${ip}`);
    if (!response || !response.ip) {
      throw new Error('Invalid ASN response');
    }
    return {
      ip: response.ip,
      asn: response.org ? `AS${response.org.match(/^AS(\d+)/)?.[1] || 'Unknown'}` : 'Unknown',
      org: response.org || 'Unknown',
    };
  }

  async fetchASNDataFromNumber(asn: string): Promise<any> {
    if (!/^AS?\d+$/i.test(asn)) {
      throw new Error(`Invalid ASN format: ${asn}`);
    }
    const cleanAsn = asn.replace(/^AS/i, '');
    const response = await this.fetchApi('asn', `/asn/AS${cleanAsn}`);
    if (!response || !response.data || !response.data.asn) {
      throw new Error('Invalid ASN response');
    }
    return {
      asn: response.data.asn || `AS${cleanAsn}`,
      org: response.data.org || 'Unknown',
    };
  }

  async fetchHybridAnalysisData(hash: string): Promise<any> {
    if (!/^[a-fA-F0-9]{64}$/.test(hash)) {
      throw new Error(`Invalid SHA-256 hash format: ${hash}`);
    }
    const response = await this.fetchApi('hybrid', `/overview/${hash}`);
    if (!response || !response.result) {
      throw new Error('Invalid Hybrid Analysis response');
    }
    return {
      result: {
        verdict: response.result.verdict || 'unknown',
        threat_score: response.result.threat_score || 0,
        submissions: response.result.submissions || 0,
      },
    };
  }

  async fetchThreatCrowdMutexData(mutex: string): Promise<any> {
    if (!mutex || typeof mutex !== 'string') {
      throw new Error('Invalid mutex value');
    }
    const response = await this.fetchApi('threatcrowd', '/mutex/report', {
      params: { resource: mutex },
    });
    if (!response || response.response_code !== '200') {
      return {
        response_code: response?.response_code || '0',
        hashes: [],
        domains: [],
      };
    }
    return {
      response_code: response.response_code,
      hashes: response.hashes || [],
      domains: response.domains || [],
    };
  }

  async fetchMispData(value: string): Promise<any> {
    if (!value || typeof value !== 'string') {
      throw new Error('Invalid search value');
    }
    const response = await this.fetchApi('misp', '/attributes/restSearch', {
      method: 'post',
      data: { value, type: 'all', includeContext: true },
    });
    if (!response || !response.response) {
      return {
        response: {
          Attribute: [],
        },
      };
    }
    return {
      response: {
        Attribute: response.response.Attribute || [],
      },
    };
  }

  async onModuleDestroy() {
    if (this.redisClient) {
      await this.redisClient.quit();
    }
  }
}
