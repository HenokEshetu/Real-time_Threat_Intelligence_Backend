import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';
import Bottleneck from 'bottleneck';
import { createClient } from 'redis';
import { GenericStixObject } from '../ingestion-from-api-feeds/feeds/feed.types';
import { TYPE_PATTERNS } from '../ingestion-from-api-feeds/feeds/feed.constants';
import { AxiosRequestConfig, AxiosError } from 'axios';
import { parse } from 'tldts';
import { isIP, isPrivate } from 'ip';
import { EventEmitter2 } from '@nestjs/event-emitter';
import CircuitBreaker from 'opossum';
import * as Joi from 'joi';

interface ApiConfig {
  url: string;
  apiKeyEnv?: string;
  requiredKey?: boolean;
  rateLimit: { maxRequests: number; perMilliseconds: number };
  headers?: Record<string, string>;
  params?: Record<string, any>;
  method?: 'get' | 'post';
  data?: any;
  timeout?: number;
  retryPolicy?: RetryPolicy;
}

interface RetryPolicy {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
}

interface EnrichmentResult {
  geo?: GeoEnrichment;
  whois?: WhoisEnrichment;
  virustotal?: VirusTotalEnrichment;
  abuseipdb?: AbuseIPDBEnrichment;
  shodan?: ShodanEnrichment;
  threatfox?: ThreatFoxEnrichment;
  dns?: DNSEnrichment;
  ssl?: SSLEnrichment;
  asn?: ASNEnrichment;
  hybrid?: HybridAnalysisEnrichment;
  threatcrowd?: ThreatCrowdEnrichment;
  misp?: MISPEnrichment;
}



// Detailed response interfaces for each enrichment service
interface GeoEnrichment {
  country_name: string;  // Changed from 'country' to 'country_name'
  country_code?: string; // Changed from 'countryCode' to 'country_code'
  region?: string;
  regionName?: string;
  city?: string;
  zip?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  as?: string;
  query: string;
}

interface WhoisEnrichment {
  WhoisRecord?: {
    registrarName?: string;
    createdDate?: string;
    updatedDate?: string;
    expiresDate?: string;
    domainName?: string;
    [key: string]: any;
  };
  [key: string]: any;
}

interface VirusTotalEnrichment {
  data?: {
    attributes?: {
      last_analysis_stats?: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
      };
      names?: string[];
      reputation?: number;
      [key: string]: any;
    };
    [key: string]: any;
  };
  [key: string]: any;
}

interface AbuseIPDBEnrichment {
  data?: {
    ipAddress: string;
    isPublic: boolean;
    ipVersion: number;
    isWhitelisted?: boolean;
    abuseConfidenceScore: number;
    countryCode?: string;
    usageType?: string;
    isp?: string;
    domain?: string;
    hostnames?: string[];
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt?: string;
    [key: string]: any;
  };
}

interface ShodanEnrichment {
  ip: string;
  ports: number[];
  hostnames?: string[];
  domains?: string[];
  os?: string;
  isp?: string;
  [key: string]: any;
}
interface ThreatFoxEnrichment {
  query_status: string;
  data?: Array<{
    ioc_value: string;    
    ioc_type: string;     
    malware: string;
    confidence_level?: number;
    first_seen?: string;  
    
    id?: string;
    malware_alias?: string[];
    malware_printable?: string;
    last_seen_utc?: string;
    reference?: string[];
    tags?: string[];
    [key: string]: any;
  }>;
}
interface DNSEnrichment {
  Status: number;
  Answer?: Array<{
    data: string;
    type: string; // Change from number to string
    TTL?: number; // Make optional to match EnrichmentData
  }>;
  Question?: Array<{
    name: string;
    type: number;
  }>;
  [key: string]: any; // Keep for flexibility
}

interface SSLEnrichment {
  host: string;
  port: number;
  protocol: string;
  grade?: string;
  serverSignature?: string;
  [key: string]: any;
}

interface ASNEnrichment {
  ip: string;
  asn: string;
  org: string;
  [key: string]: any;
}

interface HybridAnalysisEnrichment {
  result?: {
    verdict?: string;
    threat_score?: number;
    analysis_start_time?: string;
    [key: string]: any;
  };
  [key: string]: any;
}

interface ThreatCrowdEnrichment {
  response_code: string;
  hashes?: string[];
  ips?: string[];
  [key: string]: any;
}

interface MISPEnrichment {
  response?: Array<{
    Event?: {
      id: string;
      info?: string;
      tags?: string[];
      [key: string]: any;
    };
    Attribute?: {
      id: string;
      type: string;
      value: string;
      [key: string]: any;
    };
    [key: string]: any;
  }>;
  [key: string]: any;
}

interface EnrichmentTask {
  service: string;
  fetchFn: (value: string) => Promise<any>;
  field: keyof EnrichmentResult;
  validator?: (value: string) => boolean;
  schema?: Joi.ObjectSchema;
  priority?: number;
}

@Injectable()
export class EnrichmentService implements OnModuleInit {
  private readonly logger = new Logger(EnrichmentService.name);
  private readonly apiKeys: Map<string, string> = new Map();
  private readonly limiters: Map<string, Bottleneck> = new Map();
  private readonly circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private redisClient: ReturnType<typeof createClient>;
  private readonly defaultCacheTtl = 3600; // 1 hour

  private readonly apiConfigs: Record<string, ApiConfig> = {
    whois: {
      url: 'https://www.whoisxmlapi.com/whoisserver/WhoisService',
      apiKeyEnv: 'WHOIS_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      params: { outputFormat: 'JSON' },
      timeout: 120000,
    },
    geo: {
      url: 'http://ip-api.com/json',
      apiKeyEnv: 'GEO_API_KEY',
      rateLimit: { maxRequests: 45, perMilliseconds: 60000 },
    },
    virustotal: {
      url: 'https://www.virustotal.com/api/v3',
      apiKeyEnv: 'VIRUSTOTAL_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 4, perMilliseconds: 60000 },
      headers: { 'x-apikey': '${apiKey}' },
    },
    abuseipdb: {
      url: 'https://api.abuseipdb.com/api/v2/check',
      apiKeyEnv: 'ABUSEIPDB_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 30, perMilliseconds: 60000 },
      headers: { Key: '${apiKey}' },
      params: { maxAgeInDays: 90 },
    },
    shodan: {
      url: 'https://api.shodan.io',
      apiKeyEnv: 'SHODAN_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      params: { key: '${apiKey}' },
    },
    threatfox: {
      url: 'https://threatfox-api.abuse.ch/api/v1',
      apiKeyEnv: 'THREATFOX_API_KEY',
      rateLimit: { maxRequests: 60, perMilliseconds: 60000 },
      method: 'post',
      headers: { 'Content-Type': 'application/json' },
    },
    hybrid: {
      url: 'https://www.hybrid-analysis.com/api/v2',
      apiKeyEnv: 'HYBRID_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      headers: { 'api-key': '${apiKey}' },
    },
    dns: {
      url: 'https://dns.google/resolve',
      apiKeyEnv: 'DNS_API_KEY',
      rateLimit: { maxRequests: 50, perMilliseconds: 60000 },
    },
    ssl: {
      url: 'https://api.ssllabs.com/api/v3/analyze',
      apiKeyEnv: undefined,
      rateLimit: { maxRequests: 25, perMilliseconds: 60000 },
      params: { all: 'done' },
    },
    asn: {
      url: 'https://ipinfo.io',
      apiKeyEnv: 'IPINFO_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 50, perMilliseconds: 60000 },
      headers: { Authorization: 'Bearer ${apiKey}' },
    },
    threatcrowd: {
      url: 'https://www.threatcrowd.org/searchApi/v2',
      apiKeyEnv: 'THREATCROWD_API_KEY',
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
    },
    misp: {
      url: 'https://your-misp-instance/api',
      apiKeyEnv: 'MISP_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 20, perMilliseconds: 60000 },
      headers: { Authorization: '${apiKey}', Accept: 'application/json' },
    },
  };

  private readonly enrichmentSchemas: Partial<Record<keyof EnrichmentResult, Joi.ObjectSchema>> = {
    geo: Joi.object({
      country: Joi.string().required(),
      countryCode: Joi.string().length(2),
      region: Joi.string(),
      regionName: Joi.string(),
      country_name: Joi.string().required(),
    country_code: Joi.string().length(2),
      city: Joi.string(),
      zip: Joi.string(),
      lat: Joi.number(),
      lon: Joi.number(),
      timezone: Joi.string(),
      isp: Joi.string(),
      org: Joi.string(),
      as: Joi.string(),
      query: Joi.string().required(),
    }).unknown(true),

    whois: Joi.object({
      WhoisRecord: Joi.object({
        registrarName: Joi.string(),
        createdDate: Joi.string(),
        updatedDate: Joi.string(),
        expiresDate: Joi.string(),
        domainName: Joi.string(),
      }).unknown(true),
    }).unknown(true),

    virustotal: Joi.object({
      data: Joi.object({
        attributes: Joi.object({
          last_analysis_stats: Joi.object({
            malicious: Joi.number().default(0),
            suspicious: Joi.number().default(0),
            undetected: Joi.number().default(0),
            harmless: Joi.number().default(0),
            timeout: Joi.number().default(0),
          }).default(),
          names: Joi.array().items(Joi.string()).default([]),
          reputation: Joi.number(),
        }).unknown(true),
      }).unknown(true),
    }),

    abuseipdb: Joi.object({
      data: Joi.object({
        ipAddress: Joi.string().required(),
        isPublic: Joi.boolean().required(),
        ipVersion: Joi.number().required(),
        isWhitelisted: Joi.boolean(),
        abuseConfidenceScore: Joi.number().required(),
        countryCode: Joi.string().length(2),
        usageType: Joi.string(),
        isp: Joi.string(),
        domain: Joi.string(),
        hostnames: Joi.array().items(Joi.string()),
        totalReports: Joi.number().required(),
        numDistinctUsers: Joi.number().required(),
        lastReportedAt: Joi.string(),
      }).unknown(true),
    }),

    shodan: Joi.object({
      ip: Joi.string().required(),
      ports: Joi.array().items(Joi.number()).required(),
      hostnames: Joi.array().items(Joi.string()),
      domains: Joi.array().items(Joi.string()),
      os: Joi.string(),
      isp: Joi.string(),
    }).unknown(true),

    threatfox: Joi.object({
      query_status: Joi.string().required(),
      data: Joi.array().items(
        Joi.object({
          ioc_value: Joi.string().required(),
          ioc_type: Joi.string().required(),
          malware: Joi.string().required(),
          confidence_level: Joi.number(),
          first_seen: Joi.string(),
          // Optional fields
          id: Joi.string(),
          malware_alias: Joi.array().items(Joi.string()),
          malware_printable: Joi.string(),
          last_seen_utc: Joi.string(),
          reference: Joi.array().items(Joi.string()),
          tags: Joi.array().items(Joi.string()),
        }).unknown(true)
      ),
    }),

    dns: Joi.object({
      Status: Joi.number().required(),
      Answer: Joi.array().items(
        Joi.object({
          data: Joi.string().required(),
          type: Joi.string().required(), // Change to string
          TTL: Joi.number(),
        })
      ),
      Question: Joi.array().items(
        Joi.object({
          name: Joi.string().required(),
          type: Joi.number().required(),
        })
      ),
    }).unknown(true),

    ssl: Joi.object({
      host: Joi.string().required(),
      port: Joi.number().required(),
      protocol: Joi.string().required(),
      grade: Joi.string(),
      serverSignature: Joi.string(),
    }).unknown(true),

    asn: Joi.object({
      ip: Joi.string().required(),
      asn: Joi.string().required(),
      org: Joi.string().required(),
    }).unknown(true),

    hybrid: Joi.object({
      result: Joi.object({
        verdict: Joi.string(),
        threat_score: Joi.number(),
        analysis_start_time: Joi.string(),
      }).unknown(true),
    }).unknown(true),

    threatcrowd: Joi.object({
      response_code: Joi.string().required(),
      hashes: Joi.array().items(Joi.string()),
      ips: Joi.array().items(Joi.string()),
    }).unknown(true),

    misp: Joi.object({
      response: Joi.array().items(
        Joi.object({
          Event: Joi.object({
            id: Joi.string().required(),
            info: Joi.string(),
            tags: Joi.array().items(Joi.string()),
          }).unknown(true),
          Attribute: Joi.object({
            id: Joi.string().required(),
            type: Joi.string().required(),
            value: Joi.string().required(),
          }).unknown(true),
        }).unknown(true)
      ),
    }).unknown(true),
  };

  private readonly enrichmentRegistry: Record<string, EnrichmentTask[]> = {
    artifact: [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash),
        schema: this.enrichmentSchemas.virustotal,
      },
      {
        service: 'hybrid',
        fetchFn: this.fetchHybridAnalysisData,
        field: 'hybrid',
        validator: (hash) => /^[a-fA-F0-9]{64}$/.test(hash),
        schema: this.enrichmentSchemas.hybrid,
      },
    ],
     'autonomous-system': [
      {
        service: 'asn',
        fetchFn: this.fetchASNDataFromNumber,
        field: 'asn',
        validator: (asn) => /^\d+$/.test(asn),
      },
    ],
    directory: [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (path) => typeof path === 'string' && path.length > 0,
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'domain-name': [
      {
        service: 'whois',
        fetchFn: this.fetchWhoisData,
        field: 'whois',
        validator: TYPE_PATTERNS['domain-name'].test.bind(TYPE_PATTERNS['domain-name']),
      },
      {
        service: 'dns',
        fetchFn: this.fetchDNSData,
        field: 'dns',
        validator: TYPE_PATTERNS['domain-name'].test.bind(TYPE_PATTERNS['domain-name']),
        schema: this.enrichmentSchemas.dns,
      },
      {
        service: 'ssl',
        fetchFn: this.fetchSSLData,
        field: 'ssl',
        validator: TYPE_PATTERNS['domain-name'].test.bind(TYPE_PATTERNS['domain-name']),
      },
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalDomainData,
        field: 'virustotal',
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'email-address': [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: TYPE_PATTERNS['email-address'].test.bind(TYPE_PATTERNS['email-address']),
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'email-message': [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (id) => typeof id === 'string' && id.length > 0,
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    file: [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash),
        schema: this.enrichmentSchemas.virustotal,
      },
      {
        service: 'threatfox',
        fetchFn: this.fetchThreatFoxData,
        field: 'threatfox',
        validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash),
      },
      {
        service: 'hybrid',
        fetchFn: this.fetchHybridAnalysisData,
        field: 'hybrid',
        validator: (hash) => /^[a-fA-F0-9]{64}$/.test(hash),
      },
    ],
    'ipv4-addr': [
      {
        service: 'geo',
        fetchFn: this.fetchGeoData,
        field: 'geo',
        validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']),
      },
      {
        service: 'abuseipdb',
        fetchFn: this.fetchAbuseIPDBData,
        field: 'abuseipdb',
        validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']),
        schema: this.enrichmentSchemas.abuseipdb,
      },
      {
        service: 'shodan',
        fetchFn: this.fetchShodanData,
        field: 'shodan',
        validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']),
      },
      {
        service: 'asn',
        fetchFn: this.fetchASNData,
        field: 'asn',
        validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']),
      },
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalIpData,
        field: 'virustotal',
        validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']),
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'ipv6-addr': [
      {
        service: 'geo',
        fetchFn: this.fetchGeoData,
        field: 'geo',
        validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']),
      },
      {
        service: 'abuseipdb',
        fetchFn: this.fetchAbuseIPDBData,
        field: 'abuseipdb',
        validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']),
        schema: this.enrichmentSchemas.abuseipdb,
      },
      {
        service: 'asn',
        fetchFn: this.fetchASNData,
        field: 'asn',
        validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']),
      },
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalIpData,
        field: 'virustotal',
        validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']),
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'mac-address': [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: TYPE_PATTERNS['mac-address'].test.bind(TYPE_PATTERNS['mac-address']),
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    mutex: [
      {
        service: 'threatcrowd',
        fetchFn: this.fetchThreatCrowdMutexData,
        field: 'threatcrowd',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    'network-traffic': [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalIpData,
        field: 'virustotal',
        validator: (ip) => TYPE_PATTERNS['ipv4-addr'].test(ip) || TYPE_PATTERNS['ipv6-addr'].test(ip),
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    process: [
      {
        service: 'hybrid',
        fetchFn: this.fetchHybridAnalysisData,
        field: 'hybrid',
        validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash),
      },
    ],
    software: [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (name) => typeof name === 'string' && name.length > 0,
        schema: this.enrichmentSchemas.virustotal,
      },
    ],

    url: [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalUrlData,
        field: 'virustotal',
        validator: TYPE_PATTERNS['url'].test.bind(TYPE_PATTERNS['url']),
        schema: this.enrichmentSchemas.virustotal,
      },
      {
        service: 'dns',
        fetchFn: this.fetchDNSDataFromUrl,
        field: 'dns',
        validator: TYPE_PATTERNS['url'].test.bind(TYPE_PATTERNS['url']),
        schema: this.enrichmentSchemas.dns,
      },
    ],
    'user-account': [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (account) => typeof account === 'string' && account.length > 0,
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'windows-registry-key': [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (key) => typeof key === 'string' && key.startsWith('HKEY_'),
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'x509-certificate': [
      {
        service: 'virustotal',
        fetchFn: this.fetchVirusTotalData,
        field: 'virustotal',
        validator: (serial) => /^[a-fA-F0-9:]+$/.test(serial),
        schema: this.enrichmentSchemas.virustotal,
      },
    ],
    'attack-pattern': [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    campaign: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    'course-of-action': [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    grouping: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    identity: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    incident: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    indicator: [
      {
        service: 'threatfox',
        fetchFn: this.fetchThreatFoxData,
        field: 'threatfox',
        validator: (pattern) => typeof pattern === 'string' && pattern.length > 0,
      },
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (pattern) => typeof pattern === 'string' && pattern.length > 0,
      },
    ],
    infrastructure: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    'intrusion-set': [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    location: [
      {
        service: 'geo',
        fetchFn: this.fetchGeoData,
        field: 'geo',
        validator: (ip) => TYPE_PATTERNS['ipv4-addr'].test(ip) || TYPE_PATTERNS['ipv6-addr'].test(ip),
      },
    ],
    malware: [
      {
        service: 'threatfox',
        fetchFn: this.fetchThreatFoxData,
        field: 'threatfox',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    'malware-analysis': [
      {
        service: 'hybrid',
        fetchFn: this.fetchHybridAnalysisData,
        field: 'hybrid',
        validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash),
      },
    ],
    note: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (content) => typeof content === 'string' && content.length > 0,
      },
    ],
    'observed-data': [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (value) => typeof value === 'string' && value.length > 0,
      },
    ],
    opinion: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (value) => typeof value === 'string' && value.length > 0,
      },
    ],
    report: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    'threat-actor': [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    tool: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (name) => typeof name === 'string' && name.length > 0,
      },
    ],
    vulnerability: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (cve) => /^CVE-\d{4}-\d{4,}$/.test(cve),
      },
    ],
    sighting: [
      {
        service: 'misp',
        fetchFn: this.fetchMispData,
        field: 'misp',
        validator: (value) => typeof value === 'string' && value.length > 0,
      },
    ],
  };

  constructor(
    private readonly configService: ConfigService,
    private readonly httpService: HttpService,
    private readonly eventEmitter: EventEmitter2,
  ) {}

  async onModuleInit() {
    await this.initializeRedis();
    this.initializeApiServices();
    this.initializeCircuitBreakers();
  }

  private async initializeRedis() {
    this.redisClient = createClient({
      url: this.configService.get<string>('REDIS_URL'),
      socket: {
        reconnectStrategy: (retries) => {
          if (retries > 5) {
            this.logger.error('Redis connection failed after 5 retries');
            return new Error('Max retries reached');
          }
          return Math.min(retries * 100, 5000);
        },
      },
    });

    this.redisClient.on('error', (err) => {
      this.logger.error('Redis error:', err);
    });

    await this.redisClient.connect();
  }

  private initializeApiServices() {
    for (const [service, config] of Object.entries(this.apiConfigs)) {
      const apiKey = config.apiKeyEnv ? this.configService.get<string>(config.apiKeyEnv) : undefined;
      if (apiKey) {
        this.apiKeys.set(service, apiKey);
        this.logger.debug(`API key loaded for ${service}`);
      } else if (config.requiredKey) {
        this.logger.warn(`Missing required API key for ${service} (${config.apiKeyEnv})`);
      }

      this.limiters.set(
        service,
        new Bottleneck({
          maxConcurrent: config.rateLimit.maxRequests,
          minTime: config.rateLimit.perMilliseconds / config.rateLimit.maxRequests,
          reservoir: config.rateLimit.maxRequests,
          reservoirRefreshAmount: config.rateLimit.maxRequests,
          reservoirRefreshInterval: config.rateLimit.perMilliseconds,
        }),
      );
    }
  }

  private initializeCircuitBreakers() {
    for (const [service, config] of Object.entries(this.apiConfigs)) {
      this.circuitBreakers.set(
        service,
        new CircuitBreaker(
          async (fn: () => Promise<any>) => fn(),
          {
            timeout: config.timeout || 10000,
            errorThresholdPercentage: 50,
            resetTimeout: 30000,
          }
        )
      );
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
      email: 'email-address',
      hostname: 'domain-name',
      ipv4: 'ipv4-addr',
      ipv6: 'ipv6-addr',
      domain: 'domain-name',
      yara: 'indicator',
    };
    return typeMap[type.toLowerCase()] || type.toLowerCase().replace('filehash-', 'file');
  }
  async enrichIndicator(indicator: GenericStixObject): Promise<GenericStixObject & { enrichment: EnrichmentResult }> {
    const primaryValue = this.getPrimaryValue(indicator);
    const cacheKey = `enrich:${indicator.type}:${primaryValue}`;

    try {
      // Check cache first
      const cached = await this.getFromCache<EnrichmentResult>(cacheKey);
      if (cached) {
        this.eventEmitter.emit('enrichment.cache.hit', { type: indicator.type, value: primaryValue });
        return { ...indicator, enrichment: cached };
      }

      // Skip private/local resources
      if (this.shouldSkipEnrichment(indicator, primaryValue)) {
        await this.setCache(cacheKey, {}); 
        return { ...indicator, enrichment: {} };
      }

      const typeKey = this.determineTypeKey(indicator, primaryValue);
      const tasks = this.getValidTasks(typeKey, primaryValue);

      if (!tasks.length) {
        this.logger.warn(`No enrichment tasks for ${typeKey}`);
        await this.setCache(cacheKey, {}); 
        return { ...indicator, enrichment: {} };
      }

      // Execute tasks in parallel with priority consideration
      const enrichment = await this.executeEnrichmentTasks(tasks, primaryValue);
      
      // Cache the result
      await this.setCache(cacheKey, enrichment);
      
      this.eventEmitter.emit('enrichment.completed', {
        type: indicator.type,
        value: primaryValue,
        services: Object.keys(enrichment)
      });

      return { ...indicator, enrichment };
    } catch (error) {
      this.logger.error(`Failed to enrich indicator ${indicator.type}:${primaryValue}`, error);
      this.eventEmitter.emit('enrichment.failed', {
        type: indicator.type,
        value: primaryValue,
        error: error.message
      });
      return { ...indicator, enrichment: {} };
    }
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
    // Skip private/local IPs
    if ((indicator.type === 'ipv4-addr' || indicator.type === 'ipv6-addr') && isIP(value) && isPrivate(value)) {
      return true;
    }

    // Skip localhost domains
    if (indicator.type === 'domain-name' && ['localhost', '127.0.0.1'].includes(value.toLowerCase())) {
      return true;
    }

    // Skip empty values
    if (!value) {
      this.logger.warn(`No value for ${indicator.type} (id: ${indicator.id})`);
      return true;
    }

    return false;
  }

  private determineTypeKey(indicator: GenericStixObject, primaryValue: string): string {
    let typeKey = this.normalizeType(indicator.type);
    if (typeKey === 'file' && TYPE_PATTERNS['url'].test(primaryValue)) {
      typeKey = 'url';
    }
    return typeKey;
  }

  private getValidTasks(typeKey: string, primaryValue: string): EnrichmentTask[] {
    const tasks = this.enrichmentRegistry[typeKey] || [];
    return tasks
      .filter(task => {
        // Skip if service requires API key but none is configured
        if (this.apiConfigs[task.service]?.requiredKey && !this.apiKeys.has(task.service)) {
          return false;
        }
        // Skip if validator fails
        if (task.validator && !task.validator(primaryValue)) {
          return false;
        }
        return true;
      })
      .sort((a, b) => (b.priority || 0) - (a.priority || 0));
  }

  private async executeEnrichmentTasks(tasks: EnrichmentTask[], primaryValue: string): Promise<EnrichmentResult> {
    const results = await Promise.allSettled(
      tasks.map(task => this.executeSingleTask(task, primaryValue))
    );

    const enrichment: EnrichmentResult = {};
    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        enrichment[tasks[index].field] = result.value;
      }
    });
    return enrichment;
  }

  private async executeSingleTask(task: EnrichmentTask, value: string): Promise<any> {
    const taskCacheKey = `task:${task.service}:${value}`;
    try {
      // Check cache first
      const cached = await this.getFromCache(taskCacheKey);
      if (cached) return cached;

      const limiter = this.limiters.get(task.service);
      if (!limiter) {
        this.logger.warn(`No rate limiter for ${task.service}`);
        return null;
      }

      const circuitBreaker = this.circuitBreakers.get(task.service);
      if (!circuitBreaker) {
        this.logger.warn(`No circuit breaker for ${task.service}`);
        return null;
      }

      // Execute with circuit breaker protection
      const result = await circuitBreaker.fire(() =>
        limiter.schedule(() => task.fetchFn.call(this, value))
      );

      if (result) {
        // Validate and normalize response
        const validatedResult = task.schema 
          ? this.validateAndNormalizeResponse(result, task.schema) 
          : result;
        
        if (validatedResult) {
          await this.setCache(taskCacheKey, validatedResult, this.getCacheTtlForService(task.service));
          return validatedResult;
        }
      }
      return null;
    } catch (error) {
      this.handleTaskError(task.service, value, error);
      return null;
    }
  }

  private validateAndNormalizeResponse(data: any, schema: Joi.ObjectSchema): any {
    const { error, value } = schema.validate(data, { stripUnknown: true });
    if (error) {
      this.logger.warn(`Response validation failed: ${error.message}`);
      return null;
    }
    return value;
  }

  private getCacheTtlForService(service: string): number {
    // Implement service-specific cache TTLs if needed
    switch (service) {
      case 'geo':
        return 86400; // 24 hours for geo data
      case 'whois':
        return 604800; // 1 week for whois data
      case 'dns':
        return 43200; // 12 hours for DNS records
      default:
        return this.defaultCacheTtl;
    }
  }

  private async getFromCache<T>(key: string): Promise<T | null> {
    try {
      const cached = await this.redisClient.get(key);
      return cached ? JSON.parse(cached) : null;
    } catch (error) {
      this.logger.error(`Cache read error for key ${key}`, error);
      return null;
    }
  }

  private async setCache(key: string, value: any, ttl?: number): Promise<void> {
    try {
      await this.redisClient.set(
        key,
        JSON.stringify(value),
        { EX: ttl || this.defaultCacheTtl }
      );
    } catch (error) {
      this.logger.error(`Cache write error for key ${key}`, error);
    }
  }

  private handleTaskError(service: string, value: string, error: any): void {
    const axiosError = error as AxiosError;
    const status = axiosError.response?.status;
    const errorMessage = status 
      ? `API error (${status}): ${axiosError.message}`
      : `Network error: ${axiosError.message}`;

    this.logger.error(`Enrichment task failed`, {
      service,
      value,
      error: errorMessage,
    });

    this.eventEmitter.emit('enrichment.error', {
      service,
      value,
      error: errorMessage
    });
  }

  
  private async fetchApi(
    service: string,
    endpoint: string,
    config: AxiosRequestConfig = {},
    retryCount = 0
  ): Promise<any> {
    const apiConfig = this.apiConfigs[service];
    if (!apiConfig) {
      throw new Error(`Unknown service: ${service}`);
    }

    const apiKey = this.apiKeys.get(service);
    const baseUrl = apiConfig.url.replace(/\/$/, '');
    const url = endpoint ? `${baseUrl}/${endpoint.replace(/^\//, '')}` : baseUrl;
    
    // Replace API key placeholders in headers and params
    const headers = {
      ...Object.fromEntries(
        Object.entries(apiConfig.headers || {}).map(([k, v]) => 
          [k, v.replace('${apiKey}', apiKey || '')]
        )
      ),
      ...(config.headers || {}),
      'User-Agent': 'CyberThreatIntelPlatform/1.0'
    };

    const params = {
      ...Object.fromEntries(
        Object.entries(apiConfig.params || {}).map(([k, v]) => 
          [k, typeof v === 'string' ? v.replace('${apiKey}', apiKey || '') : v]
        )
      ),
      ...(config.params || {})
    };

    const requestConfig: AxiosRequestConfig = {
      method: config.method || apiConfig.method || 'get',
      url,
      headers,
      params,
      data: config.data || apiConfig.data,
      timeout: apiConfig.timeout || 15000,
    };

    try {
      const response = await firstValueFrom(this.httpService.request(requestConfig));
      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      
      // Don't retry for client errors (except 429)
      if (axiosError.response?.status && 
          axiosError.response.status >= 400 && 
          axiosError.response.status < 500 &&
          axiosError.response.status !== 429) {
        throw axiosError;
      }

      // Implement retry logic
      const retryPolicy = apiConfig.retryPolicy || {
        maxRetries: 3,
        baseDelay: 1000,
        maxDelay: 10000
      };

      if (retryCount < retryPolicy.maxRetries) {
        const delay = Math.min(
          retryPolicy.baseDelay * Math.pow(2, retryCount) + Math.random() * 1000,
          retryPolicy.maxDelay
        );
        await new Promise(resolve => setTimeout(resolve, delay));
        return this.fetchApi(service, endpoint, config, retryCount + 1);
      }

      throw axiosError;
    }
  }

  // Service-specific fetch methods
  async fetchWhoisData(domain: string): Promise<WhoisEnrichment> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }

    const response = await this.fetchApi('whois', '', {
      params: { domainName: domain }
    });

    if (!response || response.ErrorMessage) {
      throw new Error(response?.ErrorMessage || 'Invalid WHOIS response');
    }

    return response;
  }
  async fetchGeoData(ip: string): Promise<GeoEnrichment> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }
  
    const response = await this.fetchApi('geo', `/${ip}`, {
      params: { fields: 'country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query' }
    });
  
    if (!response || !response.country) {
      throw new Error('Invalid GeoIP response');
    }
  
    return {
      country_name: response.country,
      country_code: response.countryCode,
      region: response.region,
      regionName: response.regionName,
      city: response.city,
      zip: response.zip,
      lat: response.lat,
      lon: response.lon,
      timezone: response.timezone,
      isp: response.isp,
      org: response.org,
      as: response.as,
      query: response.query,
    };
  }
  async fetchVirusTotalData(hash: string): Promise<VirusTotalEnrichment> {
    if (!/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash)) {
      throw new Error(`Invalid hash format: ${hash}`);
    }

    const response = await this.fetchApi('virustotal', `/files/${hash}`);
    
    if (!response || !response.data) {
      throw new Error('Invalid VirusTotal response');
    }

    return response;
  }

  async fetchVirusTotalIpData(ip: string): Promise<VirusTotalEnrichment> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }

    const response = await this.fetchApi('virustotal', `/ip_addresses/${ip}`);
    
    if (!response || !response.data) {
      throw new Error('Invalid VirusTotal response');
    }

    return response;
  }

  async fetchVirusTotalDomainData(domain: string): Promise<VirusTotalEnrichment> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }

    const response = await this.fetchApi('virustotal', `/domains/${domain}`);
    
    if (!response || !response.data) {
      throw new Error('Invalid VirusTotal response');
    }

    return response;
  }

  async fetchVirusTotalUrlData(url: string): Promise<VirusTotalEnrichment> {
    if (!TYPE_PATTERNS['url'].test(url)) {
      throw new Error(`Invalid URL format: ${url}`);
    }

    // Step 1: Submit URL for analysis
    const initialResponse = await this.fetchApi('virustotal', '/urls', {
      method: 'post',
      data: { url }
    });

    const analysisId = initialResponse?.data?.id;
    if (!analysisId) {
      throw new Error('Failed to get analysis ID from VirusTotal');
    }

    // Step 2: Poll for analysis results
    const maxAttempts = 5;
    const delayMs = 5000;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
      
      try {
        const result = await this.fetchApi('virustotal', `/analyses/${analysisId}`);
        if (result?.data?.attributes?.status === 'completed') {
          return result;
        }
      } catch (error) {
        this.logger.warn(`VirusTotal analysis poll attempt ${attempt + 1} failed`, error);
      }
    }

    throw new Error(`VirusTotal URL analysis timed out after ${maxAttempts * delayMs / 1000} seconds`);
  }

  async fetchAbuseIPDBData(ip: string): Promise<AbuseIPDBEnrichment> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }

    const response = await this.fetchApi('abuseipdb', '', {
      params: { ipAddress: ip, maxAgeInDays: 90 }
    });

    if (!response || !response.data) {
      throw new Error('Invalid AbuseIPDB response');
    }

    return response;
  }

  async fetchShodanData(ip: string): Promise<ShodanEnrichment> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }

    const response = await this.fetchApi('shodan', '/shodan/host', {
      params: { ip }
    });

    if (!response) {
      throw new Error('Invalid Shodan response');
    }

    return response;
  }

  async fetchThreatFoxData(ioc: string): Promise<ThreatFoxEnrichment> {
    if (!ioc || typeof ioc !== 'string') {
      throw new Error('Invalid IOC value');
    }
  
    const response = await this.fetchApi('threatfox', '', {
      method: 'post',
      data: { query: 'search_ioc', search_term: ioc }
    });
  
    if (!response || response.query_status !== 'ok') {
      throw new Error(response?.query_status || 'Invalid ThreatFox response');
    }
  
    // Transform the response to match our interface
    if (response.data) {
      response.data = response.data.map(item => ({
        ioc_value: item.ioc,
        ioc_type: item.threat_type,
        malware: item.malware,
        confidence_level: item.confidence_level,
        first_seen: item.first_seen_utc,
        // Preserve other fields
        id: item.id,
        malware_alias: item.malware_alias,
        malware_printable: item.malware_printable,
        last_seen_utc: item.last_seen_utc,
        reference: item.reference,
        tags: item.tags,
      }));
    }
  
    return response;
  }

  async fetchDNSData(domain: string): Promise<DNSEnrichment> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }
  
    const parsed = parse(domain);
    if (!parsed.domain) {
      throw new Error(`Invalid domain: ${domain}`);
    }
  
    const cacheKey = `dns:${parsed.domain}`;
    const cached = await this.getFromCache<DNSEnrichment>(cacheKey);
    if (cached) {
      return cached;
    }
  
    const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'];
    const responses = await Promise.all(
      recordTypes.map(type =>
        this.fetchApi('dns', '', {
          params: { name: parsed.domain, type },
          timeout: 30000,
        })
      )
    );
  
    // Map DNS type numbers to strings
    const typeMap: Record<number, string> = {
      1: 'A',
      5: 'CNAME',
      15: 'MX',
      2: 'NS',
      16: 'TXT',
      28: 'AAAA',
      // Add more mappings as needed
    };
  
    const answers = responses
      .filter(res => res?.Status === 0 && res?.Answer)
      .flatMap(res => res.Answer)
      .filter(answer => answer.data && typeof answer.data === 'string')
      .map(answer => ({
        data: answer.data,
        type: typeMap[answer.type] || answer.type.toString(), // Convert number to string
        TTL: answer.TTL,
      }));
  
    const questions = responses
      .filter(res => res?.Question)
      .flatMap(res => res.Question)
      .map(question => ({
        name: question.name,
        type: question.type,
      }));
  
    if (answers.length === 0) {
      await this.setCache(cacheKey, { Status: 2 }, 3600); // Cache negative result
      throw new Error('No DNS records found');
    }
  
    const result: DNSEnrichment = {
      Status: 0,
      Answer: answers,
      Question: questions.length > 0 ? questions : undefined,
    };
  
    await this.setCache(cacheKey, result, 86400);
    return result;
  }

  async fetchDNSDataFromUrl(url: string): Promise<DNSEnrichment> {
    if (!TYPE_PATTERNS['url'].test(url)) {
      throw new Error(`Invalid URL format: ${url}`);
    }
  
    const parsed = parse(url);
    const domain = parsed.domain || url.split('/')[2];
    if (!domain || !TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Could not extract domain from URL: ${url}`);
    }
  
    return this.fetchDNSData(domain);
  }
  async fetchSSLData(domain: string): Promise<SSLEnrichment> {
    if (!TYPE_PATTERNS['domain-name'].test(domain)) {
      throw new Error(`Invalid domain format: ${domain}`);
    }

    const parsed = parse(domain);
    if (!parsed.domain) {
      throw new Error(`Invalid domain: ${domain}`);
    }

    const cacheKey = `ssl:${parsed.domain}`;
    const cached = await this.getFromCache<SSLEnrichment>(cacheKey);
    if (cached) {
      return cached;
    }

    // Start SSL analysis
    const startResponse = await this.fetchApi('ssl', '', {
      params: { host: parsed.domain, startNew: 'on', all: 'done' }
    });

    if (!startResponse || startResponse.status === 'ERROR') {
      await this.setCache(cacheKey, { host: parsed.domain, status: 'ERROR' }, 3600);
      throw new Error('Failed to start SSL analysis');
    }

    // Poll for results
    const maxAttempts = 10;
    const delayMs = 10000;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await new Promise(resolve => setTimeout(resolve, delayMs));
      
      try {
        const result = await this.fetchApi('ssl', '', {
          params: { host: parsed.domain }
        });

        if (result.status === 'READY') {
          await this.setCache(cacheKey, result, 86400);
          return result;
        }
        if (result.status === 'ERROR') {
          throw new Error('SSL analysis failed');
        }
      } catch (error) {
        this.logger.warn(`SSL analysis poll attempt ${attempt + 1} failed`, error);
      }
    }

    throw new Error(`SSL analysis timed out after ${maxAttempts * delayMs / 1000} seconds`);
  }

  async fetchASNData(ip: string): Promise<ASNEnrichment> {
    if (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip)) {
      throw new Error(`Invalid IP format: ${ip}`);
    }

    const response = await this.fetchApi('asn', `/${ip}/json`);
    
    if (!response || !response.asn) {
      throw new Error('Invalid ASN response');
    }

    return response;
  }

  async fetchASNDataFromNumber(asn: string): Promise<ASNEnrichment> {
    if (!/^AS?\d+$/i.test(asn)) {
      throw new Error(`Invalid ASN format: ${asn}`);
    }

    const cleanAsn = asn.replace(/^AS/i, '');
    const response = await this.fetchApi('asn', `/AS${cleanAsn}/json`);
    
    if (!response || !response.asn) {
      throw new Error('Invalid ASN response');
    }

    return response;
  }

  async fetchHybridAnalysisData(hash: string): Promise<HybridAnalysisEnrichment> {
    if (!/^[a-fA-F0-9]{64}$/.test(hash)) {
      throw new Error(`Invalid SHA-256 hash format: ${hash}`);
    }

    const response = await this.fetchApi('hybrid', `/overview/${hash}`);
    
    if (!response || !response.result) {
      throw new Error('Invalid Hybrid Analysis response');
    }

    return response;
  }

  async fetchThreatCrowdMutexData(mutex: string): Promise<ThreatCrowdEnrichment> {
    if (!mutex || typeof mutex !== 'string') {
      throw new Error('Invalid mutex value');
    }

    const response = await this.fetchApi('threatcrowd', '/mutex/report', {
      params: { resource: mutex }
    });

    if (!response || response.response_code !== '200') {
      throw new Error(response?.response_code || 'Invalid ThreatCrowd response');
    }

    return response;
  }

  async fetchMispData(value: string): Promise<MISPEnrichment> {
    if (!value || typeof value !== 'string') {
      throw new Error('Invalid search value');
    }

    const response = await this.fetchApi('misp', '/attributes/restSearch', {
      method: 'post',
      data: { value, type: 'all', includeContext: true }
    });

    if (!response || !response.response) {
      throw new Error('Invalid MISP response');
    }

    return response;
  }

  async onModuleDestroy() {
    if (this.redisClient) {
      await this.redisClient.quit();
    }
  }
}