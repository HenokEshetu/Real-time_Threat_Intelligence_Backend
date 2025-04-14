// src/enrichment/enrichment.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import Bottleneck from 'bottleneck';
import NodeCache from 'node-cache';
import { GenericStixObject } from '../ingestion-from-api-feeds/feeds/feed.types';
import { TYPE_PATTERNS } from '../ingestion-from-api-feeds/feeds/feed.constants';
import { AxiosRequestConfig } from 'axios';
import { parse } from 'tldts';

export const API_CONFIGS = {
  whois: { url: 'https://www.whoisxmlapi.com/whoisserver/WhoisService', apiKeyEnv: 'WHOIS_API_KEY', rateLimit: { maxRequests: 10, perMilliseconds: 60000 }, params: { outputFormat: 'JSON', domainName: '' } },
  geo: { url: 'http://ip-api.com/json', apiKeyEnv: 'GEO_API_KEY', rateLimit: { maxRequests: 45, perMilliseconds: 60000 } },
  virustotal: { url: 'https://www.virustotal.com/api/v3', apiKeyEnv: 'VIRUSTOTAL_API_KEY', rateLimit: { maxRequests: 4, perMilliseconds: 60000 }, headers: { 'x-apikey': '' } },
  abuseipdb: { url: 'https://api.abuseipdb.com/api/v2/check', apiKeyEnv: 'ABUSEIPDB_API_KEY', rateLimit: { maxRequests: 30, perMilliseconds: 60000 }, headers: { Key: '' }, params: { maxAgeInDays: 90 } },
  shodan: { url: 'https://api.shodan.io/shodan/host', apiKeyEnv: 'SHODAN_API_KEY', rateLimit: { maxRequests: 10, perMilliseconds: 60000 } },
  threatfox: {
    url: 'https://threatfox-api.abuse.ch/api/v1',
    apiKeyEnv: 'THREATFOX_API_KEY',
    rateLimit: { maxRequests: 120, perMilliseconds: 60000 },
    method: 'post',
    headers: { 'Content-Type': 'application/json' }
  },
  hybrid: {
    url: 'https://www.hybrid-analysis.com/api',
    apiKeyEnv: 'HYBRID_API_KEY',
    rateLimit: { maxRequests: 15, perMilliseconds: 60000 },
    headers: { 'api-key': '' },
    method: 'post'
  },
  dns: { url: 'https://dns.google/resolve', apiKeyEnv: 'DNS_API_KEY', rateLimit: { maxRequests: 50, perMilliseconds: 60000 } },
  ssl: { url: 'https://api.ssllabs.com/api/v3/analyze', apiKeyEnv: 'SSL_API_KEY', rateLimit: { maxRequests: 25, perMilliseconds: 60000 }, params: { all: 'done' } },
  asn: { url: 'https://ipinfo.io', apiKeyEnv: 'IPINFO_API_KEY', rateLimit: { maxRequests: 50, perMilliseconds: 60000 } },
  threatcrowd: { url: 'https://www.threatcrowd.org', apiKeyEnv: 'THREATCROWD_API_KEY', rateLimit: { maxRequests: 10, perMilliseconds: 60000 } },
  misp: { url: 'https://your-misp-instance/api', apiKeyEnv: 'MISP_API_KEY', rateLimit: { maxRequests: 20, perMilliseconds: 60000 }, headers: { 'Authorization': '', 'Accept': 'application/json' } },
};

interface ApiConfig {
 url: string;
 apiKeyEnv: string;
 rateLimit: { maxRequests: number; perMilliseconds: number };
 headers?: Record<string, string>;
 params?: Record<string, any>;
 method?: 'get' | 'post';
}


interface EnrichmentResult {
 geo?: { country_name: string; lat?: number; lon?: number; [key: string]: any };
 whois?: { WhoisRecord?: { registrarName?: string; createdDate?: string; [key: string]: any }; [key: string]: any };
 virustotal?: { data?: { attributes?: { last_analysis_stats?: { malicious: number; undetected?: number; total?: number; names?: string[]; [key: string]: any }; [key: string]: any }; [key: string]: any }; [key: string]: any };
 abuseipdb?: { data?: { totalReports?: number; abuseConfidenceScore?: number; [key: string]: any }; [key: string]: any };
 shodan?: { hostnames?: string[]; ports?: number[]; [key: string]: any };
 threatfox?: { data?: any[]; [key: string]: any };
 dns?: { Answer?: { data: string; type: string; [key: string]: any }[]; [key: string]: any };
 ssl?: { endpoints?: { grade?: string; protocols?: { name: string; version: string }[]; [key: string]: any }[]; [key: string]: any };
 asn?: { asn?: string; org?: string; [key: string]: any };
 hybrid?: { summary?: { environment?: string; threat_score?: number; [key: string]: any }; [key: string]: any };
 threatcrowd?: { hashes?: string[]; ips?: string[]; [key: string]: any };
 misp?: { events?: { Event?: { info?: string; tags?: string[]; [key: string]: any }[] }[] };
}


type EnrichmentTask = {
 service: string;
 fetchFn: (value: string) => Promise<any>;
 field: keyof EnrichmentResult;
 validator?: (value: string) => boolean;
};


@Injectable()
export class EnrichmentService {
 private readonly logger = new Logger(EnrichmentService.name);
 private readonly apiKeys: Map<string, string> = new Map();
 private readonly limiters: Map<string, Bottleneck> = new Map();
 private readonly cache = new NodeCache({ stdTTL: 3600, checkperiod: 120 });
 private readonly maxRetries = parseInt(process.env.ENRICHMENT_MAX_RETRIES || '3', 10);
 private readonly apiConfigs = API_CONFIGS;


 private readonly enrichmentRegistry: Record<string, EnrichmentTask[]> = {
   'artifact': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash) },
   ],
   'autonomous-system': [
     { service: 'asn', fetchFn: this.fetchASNDataFromNumber, field: 'asn', validator: (asn) => /^\d+$/.test(asn) },
   ],
   'directory': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (path) => typeof path === 'string' && path.length > 0 },
   ],
   'domain-name': [
     { service: 'whois', fetchFn: this.fetchWhoisData, field: 'whois', validator: TYPE_PATTERNS['domain-name'].test.bind(TYPE_PATTERNS['domain-name']) },
     { service: 'dns', fetchFn: this.fetchDNSData, field: 'dns', validator: TYPE_PATTERNS['domain-name'].test.bind(TYPE_PATTERNS['domain-name']) },
     { service: 'ssl', fetchFn: this.fetchSSLData, field: 'ssl', validator: TYPE_PATTERNS['domain-name'].test.bind(TYPE_PATTERNS['domain-name']) },
     { service: 'virustotal', fetchFn: this.fetchVirusTotalIpData, field: 'virustotal' },
   ],
   'email-address': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: TYPE_PATTERNS['email-address'].test.bind(TYPE_PATTERNS['email-address']) },
   ],
   'email-message': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (id) => typeof id === 'string' && id.length > 0 },
   ],
   'file': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash) },
     { service: 'threatfox', fetchFn: this.fetchThreatFoxData, field: 'threatfox', validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash) },
     { service: 'hybrid', fetchFn: this.fetchHybridAnalysisData, field: 'hybrid', validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash) },
   ],
   'ipv4-addr': [
     { service: 'geo', fetchFn: this.fetchGeoData, field: 'geo', validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']) },
     { service: 'abuseipdb', fetchFn: this.fetchAbuseIPDBData, field: 'abuseipdb', validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']) },
     { service: 'shodan', fetchFn: this.fetchShodanData, field: 'shodan', validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']) },
     { service: 'asn', fetchFn: this.fetchASNData, field: 'asn', validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']) },
     { service: 'virustotal', fetchFn: this.fetchVirusTotalIpData, field: 'virustotal', validator: TYPE_PATTERNS['ipv4-addr'].test.bind(TYPE_PATTERNS['ipv4-addr']) },
   ],
   'ipv6-addr': [
     { service: 'geo', fetchFn: this.fetchGeoData, field: 'geo', validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']) },
     { service: 'abuseipdb', fetchFn: this.fetchAbuseIPDBData, field: 'abuseipdb', validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']) },
     { service: 'asn', fetchFn: this.fetchASNData, field: 'asn', validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']) },
     { service: 'virustotal', fetchFn: this.fetchVirusTotalIpData, field: 'virustotal', validator: TYPE_PATTERNS['ipv6-addr'].test.bind(TYPE_PATTERNS['ipv6-addr']) },
   ],
   'mac-address': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: TYPE_PATTERNS['mac-address'].test.bind(TYPE_PATTERNS['mac-address']) },
   ],
   'mutex': [
     { service: 'threatcrowd', fetchFn: this.fetchThreatCrowdMutexData, field: 'threatcrowd', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'network-traffic': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalIpData, field: 'virustotal', validator: (ip) => TYPE_PATTERNS['ipv4-addr'].test(ip) || TYPE_PATTERNS['ipv6-addr'].test(ip) },
   ],
   'process': [
     { service: 'hybrid', fetchFn: this.fetchHybridAnalysisData, field: 'hybrid', validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash) },
   ],
   'software': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'url': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalUrlData, field: 'virustotal', validator: TYPE_PATTERNS['url'].test.bind(TYPE_PATTERNS['url']) },
     { service: 'dns', fetchFn: this.fetchDNSDataFromUrl, field: 'dns', validator: TYPE_PATTERNS['url'].test.bind(TYPE_PATTERNS['url']) },
   ],
   'user-account': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (account) => typeof account === 'string' && account.length > 0 },
   ],
   'windows-registry-key': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (key) => typeof key === 'string' && key.startsWith('HKEY_') },
   ],
   'x509-certificate': [
     { service: 'virustotal', fetchFn: this.fetchVirusTotalData, field: 'virustotal', validator: (serial) => /^[a-fA-F0-9:]+$/.test(serial) },
   ],
   'attack-pattern': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'campaign': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'course-of-action': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'grouping': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'identity': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'incident': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'indicator': [
     { service: 'threatfox', fetchFn: this.fetchThreatFoxData, field: 'threatfox', validator: (pattern) => typeof pattern === 'string' && pattern.length > 0 },
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (pattern) => typeof pattern === 'string' && pattern.length > 0 },
   ],
   'infrastructure': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'intrusion-set': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'location': [
     { service: 'geo', fetchFn: this.fetchGeoData, field: 'geo', validator: (ip) => TYPE_PATTERNS['ipv4-addr'].test(ip) || TYPE_PATTERNS['ipv6-addr'].test(ip) },
   ],
   'malware': [
     { service: 'threatfox', fetchFn: this.fetchThreatFoxData, field: 'threatfox', validator: (name) => typeof name === 'string' && name.length > 0 },
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'malware-analysis': [
     { service: 'hybrid', fetchFn: this.fetchHybridAnalysisData, field: 'hybrid', validator: (hash) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash) },
   ],
   'note': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (content) => typeof content === 'string' && content.length > 0 },
   ],
   'observed-data': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (value) => typeof value === 'string' && value.length > 0 },
   ],
   'opinion': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (value) => typeof value === 'string' && value.length > 0 },
   ],
   'report': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'threat-actor': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'tool': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (name) => typeof name === 'string' && name.length > 0 },
   ],
   'vulnerability': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (cve) => /^CVE-\d{4}-\d{4,}$/.test(cve) },
   ],
   'sighting': [
     { service: 'misp', fetchFn: this.fetchMispData, field: 'misp', validator: (value) => typeof value === 'string' && value.length > 0 },
   ],
 };
 constructor(
   private readonly configService: ConfigService,
   private readonly httpService: HttpService,
 ) {
   this.logger.debug('HttpService injected:', !!this.httpService);
   this.logger.debug('axiosRef available:', !!this.httpService?.axiosRef);
   if (!this.httpService || !this.httpService.axiosRef) {
     this.logger.error('HttpService or axiosRef is undefined during initialization!');
   }


   for (const [service, config] of Object.entries(this.apiConfigs)) {
     const apiKey = this.configService.get<string>(config.apiKeyEnv);
     if (apiKey) {
       this.apiKeys.set(service, apiKey);
       this.logger.debug(`API key loaded for ${service}: ${apiKey.substring(0, 4)}...`);
     } else if (config.apiKeyEnv) {
       this.logger.warn(`API key for ${service} not found in environment variable ${config.apiKeyEnv}`);
     }
     this.limiters.set(
       service,
       new Bottleneck({
         maxConcurrent: config.rateLimit.maxRequests,
         minTime: config.rateLimit.perMilliseconds / config.rateLimit.maxRequests,
       }),
     );
   }
 }




 private normalizeType(type: string): string {
   const typeMap: Record<string, string> = {
     'filemd5': 'file',
     'filesha1': 'file',
     'filesha256': 'file',
     'filesha512': 'file',
     'filehash-md5': 'file',
     'filehash-sha1': 'file',
     'filehash-sha256': 'file',
     'filehash-sha512': 'file',
     'email': 'email-address',
     'hostname': 'domain-name',
     'ipv4': 'ipv4-addr',
     'ipv6': 'ipv6-addr',
     'domain': 'domain-name',
     'yara': 'indicator',
   };
   return typeMap[type.toLowerCase()] || type.toLowerCase().replace('filehash-', 'file');
 }
 async enrichIndicator(indicator: GenericStixObject): Promise<GenericStixObject & { enrichment: EnrichmentResult }> {
  let primaryValue: string;
  if (indicator.type === 'file' || this.normalizeType(indicator.type) === 'file') {
    primaryValue = (
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
  } else {
    primaryValue = indicator.indicator || indicator.value || indicator.name || Object.values(indicator.hashes || {})[0] || '';
  }

  const cacheKey = `${indicator.type}-${primaryValue}`;
  const cached = this.cache.get<EnrichmentResult>(cacheKey);
  if (cached) {
    this.logger.debug(`Cache hit for ${indicator.type}:${primaryValue}`);
    return { ...indicator, enrichment: cached };
  }

  let typeKey = this.normalizeType(indicator.type);
  if (typeKey === 'file' && TYPE_PATTERNS['url'].test(primaryValue)) {
    typeKey = 'url';
  }

  const tasks = this.enrichmentRegistry[typeKey] || [];
  if (!tasks.length) {
    this.logger.warn(`No enrichment tasks for ${typeKey}`);
    return { ...indicator, enrichment: {} };
  }

  const results = await Promise.allSettled(
    tasks.map(task => {
      if (task.validator && !task.validator(primaryValue)) {
        return Promise.resolve(null);
      }
      const limiter = this.limiters.get(task.service);
      if (!limiter) {
        this.logger.warn(`No limiter for ${task.service}`);
        return Promise.resolve(null);
      }
      return limiter.schedule(() =>
        task.fetchFn.bind(this)(primaryValue).catch(error => {
          this.handleEnrichmentError(task.service, error);
          return null;
        })
      );
    })
  );

  const enrichment: EnrichmentResult = {};
  results.forEach((result, index) => {
    if (result.status === 'fulfilled' && result.value) {
      enrichment[tasks[index].field] = result.value;
    }
  });

  this.cache.set(cacheKey, enrichment);
  this.logger.log(`Enriched ${typeKey}:${primaryValue} with ${Object.keys(enrichment).length} services`);
  return { ...indicator, enrichment };
}

private async fetchApi(service: string, endpoint: string, config: AxiosRequestConfig = {}, retryCount = 0): Promise<any> {
  const apiConfig = this.apiConfigs[service];
  if (!apiConfig) throw new Error(`Unknown service: ${service}`);

  const apiKey = this.apiKeys.get(service);
  const url = `${apiConfig.url}${endpoint}`;
  const headers = {
    ...apiConfig.headers,
    ...(config.headers || {}),
    'User-Agent': 'Enrichment/1.0',
  };

  const requestConfig: AxiosRequestConfig = {
    method: config.method || apiConfig.method || 'get',
    url,
    headers,
    params: {
      ...apiConfig.params,
      ...(apiKey ? { apiKey } : {}),
      ...(config.params || {}),
    },
    data: config.data || apiConfig.data,
    timeout: 60000,
  };

  try {
    if (service === 'threatfox' && requestConfig.method === 'post') {
      const response = await this.httpService.post(url, requestConfig.data, { headers, timeout: 60000 }).toPromise();
      return response.data;
    }
    const response = await this.httpService.axiosRef.request(requestConfig);
    return response.data;
  } catch (error) {
    const axiosError = error as import('axios').AxiosError;
    const isNetworkError = axiosError.code === 'ECONNREFUSED' || axiosError.code === 'EAI_AGAIN';
    if ((axiosError.response?.status === 429 || isNetworkError) && retryCount < this.maxRetries) {
      const delay = Math.pow(2, retryCount) * 1000 + Math.random() * 1000;
      this.logger.warn(`Retry ${service} after ${delay.toFixed(0)}ms (attempt ${retryCount + 1}/${this.maxRetries})`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.fetchApi(service, endpoint, config, retryCount + 1);
    }
    this.logger.error(`Failed ${service} request: ${axiosError.message}`);
    throw axiosError;
  }
}




 private handleEnrichmentError(service: string, error: any): void {
   const message = error.response ? JSON.stringify(error.response.data) : error.message;
   this.logger.error(`Enrichment failed for ${service}: ${message}`);
 }


 async fetchWhoisData(domain: string): Promise<any> {
   const limiter = this.limiters.get('whois');
   if (!limiter) {
     this.logger.warn('No limiter found for whois');
     return null;
   }
   return limiter.schedule(() =>
     this.fetchApi('whois', '', {
       params: { domainName: domain },
     })
     .then(data => {
       this.logger.debug(`Whois response: ${JSON.stringify(data)}`);
       return data;
     })
     .catch(error => {
       this.handleEnrichmentError('whois', error);
       return null;
     })
   );
 }
 async fetchGeoData(ip: string): Promise<any> {
   const key = this.apiKeys.get('geo');
   return this.fetchApi('geo', `/${ip}`, key ? { params: { fields: 'country,lat,lon' } } : {});
 }


 async fetchVirusTotalData(hash: string): Promise<any> {
   const key = this.apiKeys.get('virustotal') || '';
   if (!key || !/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash)) return null;
   return this.fetchApi('virustotal', `/files/${hash}`);
 }


 async fetchVirusTotalIpData(ip: string): Promise<any> {
   const key = this.apiKeys.get('virustotal') || '';
   if (!key || (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip))) return null;
   return this.fetchApi('virustotal', `/ip_addresses/${ip}`);
 }


 async fetchVirusTotalUrlData(url: string): Promise<any> {
   const key = this.apiKeys.get('virustotal') || '';
   if (!key || !TYPE_PATTERNS['url'].test(url)) return null;
   const encodedUrl = Buffer.from(url).toString('base64');
   const initialResponse = await this.fetchApi('virustotal', '/urls', { method: 'post', data: { url } });
   const analysisId = initialResponse?.data?.id;
   if (!analysisId) return null;


   for (let i = 0; i < 5; i++) {
     const result = await this.fetchApi('virustotal', `/analyses/${analysisId}`);
     if (result?.data?.attributes?.status === 'completed') return result;
     await new Promise(resolve => setTimeout(resolve, 5000));
   }
   this.logger.warn(`VirusTotal URL analysis timed out for ${url}`);
   return null;
 }


 async fetchAbuseIPDBData(ip: string): Promise<any> {
   const key = this.apiKeys.get('abuseipdb') || '';
   if (!key || (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip))) return null;
   return this.fetchApi('abuseipdb', '', { params: { ipAddress: ip } });
 }


 async fetchShodanData(ip: string): Promise<any> {
   const limiter = this.limiters.get('shodan');
   if (!limiter) {
     this.logger.warn('No limiter found for shodan');
     return null;
   }
   const endpoint = '/dns/resolve'; // Free-tier endpoint
   return limiter.schedule(() =>
     this.fetchApi('shodan', endpoint, {
       params: { hostnames: ip },
     })
     .then(data => {
       this.logger.debug(`Shodan response: ${JSON.stringify(data)}`);
       return data;
     })
     .catch(error => {
       this.handleEnrichmentError('shodan', error);
       return null;
     })
   );
 }
 async fetchThreatFoxData(ioc: string): Promise<any> {
   const limiter = this.limiters.get('threatfox');
   if (!limiter) {
     this.logger.warn('No limiter found for threatfox');
     return null;
   }
   return limiter.schedule(() =>
     this.fetchApi('threatfox', '', {
       method: 'post',
       headers: { 'Content-Type': 'application/json' },
       data: { query: 'search_ioc', search_term: ioc },
     })
     .then(data => {
       this.logger.debug(`ThreatFox response: ${JSON.stringify(data)}`);
       return data;
     })
     .catch(error => {
       this.handleEnrichmentError('threatfox', error);
       return null;
     })
   );
 }
 async fetchThreatFoxYaraData(): Promise<any> {
   const key = this.apiKeys.get('threatfox') || '';
   if (!key) return null;
   return this.fetchApi('threatfox', '', { data: { query: 'get_yara_rules' } });
 }


 async fetchDNSData(domain: string): Promise<any> {
   const key = this.apiKeys.get('dns') || '';
   if (!key || !TYPE_PATTERNS['domain-name'].test(domain)) return null;
   return this.fetchApi('dns', '', { params: { name: domain, type: 'A,AAAA,CNAME' } });
 }


 async fetchDNSDataFromUrl(url: string): Promise<any> {
   const domainMatch = url.match(/^(?:https?:\/\/)?([^\/]+)/);
   const domain = domainMatch ? domainMatch[1] : url;
   return this.fetchDNSData(domain);
 }


 async fetchSSLData(domain: string): Promise<any> {
   const key = this.apiKeys.get('ssl') || '';
   if (!key || !TYPE_PATTERNS['domain-name'].test(domain)) return null;
   return this.fetchApi('ssl', '', { params: { host: domain } });
 }


 async fetchASNData(ip: string): Promise<any> {
   const key = this.apiKeys.get('ipinfo') || '';
   if (!key || (!TYPE_PATTERNS['ipv4-addr'].test(ip) && !TYPE_PATTERNS['ipv6-addr'].test(ip))) return null;
   return this.fetchApi('asn', `/${ip}/json`, { params: { token: key } });
 }


 async fetchASNDataFromNumber(asn: string): Promise<any> {
   const key = this.apiKeys.get('ipinfo') || '';
   if (!key || !/^\d+$/.test(asn)) return null;
   return this.fetchApi('asn', `/AS${asn}/json`, { params: { token: key } });
 }


 async fetchHybridAnalysisData(hash: string): Promise<any> {
   const key = this.apiKeys.get('hybrid') || '';
   if (!key || !/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(hash)) return null;
   return this.fetchApi('hybrid', '/search/hash', { data: { hash } });
 }


 async fetchThreatCrowdMutexData(mutex: string): Promise<any> {
   const key = this.apiKeys.get('threatcrowd') || '';
   if (!key || !mutex) return null;
   return this.fetchApi('threatcrowd', `/search.php`, { params: { mutex, api_key: key } });
 }


 async fetchMispData(value: string): Promise<any> {
   const key = this.apiKeys.get('misp') || '';
   if (!key || !value) return null;
   return this.fetchApi('misp', '/attributes/restSearch', { data: { value, type: 'all' } });
 }
}

