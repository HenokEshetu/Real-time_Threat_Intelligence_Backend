// src/config/enrichment.config.ts
import * as Joi from 'joi';
import { EnrichmentConfig } from './enrichment-config.interface';

export const conciseResponseFields: Record<string, string[]> = {
  geo: ['country_name', 'country_code', 'city', 'lat', 'lon'],
  whois: ['domainName', 'registrarName', 'createdDate', 'expiresDate'],
  virustotal: [
    'data.attributes.last_analysis_stats',
    'data.attributes.reputation',
  ],
  abuseipdb: [
    'data.abuseConfidenceScore',
    'data.countryCode',
    'data.totalReports',
  ],
  shodan: ['ip', 'org', 'os'],
  threatfox: ['query_status', 'data.threat_type', 'data.malware'],
  dns: ['Answer.data', 'Answer.type', 'Answer.TTL'],
  ssl: ['host', 'endpoints.serverName', 'endpoints.grade'],
  asn: ['asn', 'org', 'ip'],
  hybrid: ['result.verdict', 'result.threat_score', 'result.submissions'],
  threatcrowd: ['response_code', 'hashes', 'domains'],
  misp: [
    'response.Attribute.value',
    'response.Attribute.type',
    'response.Attribute.category',
  ],
};

export const enrichmentConfig: EnrichmentConfig = {
  apiConfigs: {
    whois: {
      url: 'https://www.whoisxmlapi.com/whoisserver/WhoisService',
      apiKeyEnv: 'WHOIS_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      params: { outputFormat: 'JSON', apiKey: '${apiKey}' },
      timeout: 120000,
      retryPolicy: { maxRetries: 3, baseDelay: 1000, maxDelay: 10000 },
    },
    geo: {
      url: 'http://ip-api.com/json',
      apiKeyEnv: 'GEO_API_KEY',
      requiredKey: false,
      rateLimit: { maxRequests: 45, perMilliseconds: 60000 },
      timeout: 15000,
    },
    virustotal: {
      url: 'https://www.virustotal.com/api/v3',
      apiKeyEnv: 'VIRUSTOTAL_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 4, perMilliseconds: 60000 }, // Matches VirusTotal free tier
      headers: { 'x-apikey': '${apiKey}' },
      timeout: 30000, // Increased for slow responses
      retryPolicy: { maxRetries: 3, baseDelay: 1000, maxDelay: 10000 },
    },
    abuseipdb: {
      url: 'https://api.abuseipdb.com/api/v2/check',
      apiKeyEnv: 'ABUSEIPDB_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 30, perMilliseconds: 60000 },
      headers: { Key: '${apiKey}' },
      params: { maxAgeInDays: 90 },
      timeout: 15000,
    },
    shodan: {
      url: 'https://api.shodan.io',
      apiKeyEnv: 'SHODAN_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      params: { key: '${apiKey}' },
      timeout: 15000,
    },
    threatfox: {
      url: 'https://threatfox-api.abuse.ch/api/v1',
      method: 'post',
      requiredKey: false,
      timeout: 15000,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      retryPolicy: { maxRetries: 3, baseDelay: 1000, maxDelay: 10000 },
    },
    hybrid: {
      url: 'https://www.hybrid-analysis.com/api/v2',
      apiKeyEnv: 'HYBRID_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      headers: { 'api-key': '${apiKey}' },
      timeout: 15000,
    },
    dns: {
      url: 'https://dns.google/resolve',
      apiKeyEnv: 'DNS_API_KEY',
      requiredKey: false,
      method: 'get',
      headers: { Accept: 'application/dns-json' },
      rateLimit: { maxRequests: 50, perMilliseconds: 60000 },
      timeout: 30000,
      retryPolicy: { maxRetries: 3, baseDelay: 1000, maxDelay: 10000 },
    },
    ssl: {
      url: 'https://api.ssllabs.com/api/v3/analyze',
      apiKeyEnv: undefined,
      requiredKey: false,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 }, // Reduced for SSL Labs limits
      params: { all: 'done' },
      timeout: 30000, // Increased for polling
      retryPolicy: { maxRetries: 3, baseDelay: 1000, maxDelay: 10000 },
    },
    asn: {
      url: 'https://ipinfo.io',
      apiKeyEnv: 'IPINFO_API_KEY',
      requiredKey: false,
      rateLimit: { maxRequests: 50, perMilliseconds: 60000 },
      headers: { Authorization: 'Bearer ${apiKey}' },
      timeout: 15000,
    },
    threatcrowd: {
      url: 'https://www.threatcrowd.org/searchApi/v2',
      apiKeyEnv: 'THREATCROWD_API_KEY',
      requiredKey: false,
      rateLimit: { maxRequests: 10, perMilliseconds: 60000 },
      timeout: 15000,
    },

    misp: {
      url: 'http://localhost',
      apiKeyEnv: 'MISP_API_KEY',
      requiredKey: true,
      rateLimit: { maxRequests: 20, perMilliseconds: 60000 },
      headers: {
        Authorization: '${apiKey}',
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      timeout: 15000,
    },
  },
  enrichmentSchemas: {
    geo: Joi.object({
      country_name: Joi.string().required(),
      country_code: Joi.string().length(2).allow('', null),
      region: Joi.string().allow('', null),
      regionName: Joi.string().allow('', null),
      city: Joi.string().allow('', null),
      zip: Joi.string().allow('', null), // Allow empty/undefined
      lat: Joi.number().allow(null),
      lon: Joi.number().allow(null),
      timezone: Joi.string().allow('', null),
      isp: Joi.string().allow('', null),
      org: Joi.string().allow('', null), // Allow empty/undefined
      as: Joi.string().allow('', null),
      query: Joi.string().required(),
    }).unknown(true),
    abuseipdb: Joi.object({
      data: Joi.object({
        ipAddress: Joi.string().required(),
        isPublic: Joi.boolean().required(),
        ipVersion: Joi.number().required(),
        isWhitelisted: Joi.any().allow(null, false, true), // Allow null/undefined
        abuseConfidenceScore: Joi.number().required(),
        countryCode: Joi.string().length(2).allow('', null),
        usageType: Joi.string().allow('', null),
        isp: Joi.string().allow('', null),
        domain: Joi.string().allow('', null),
        hostnames: Joi.array().items(Joi.string().allow('')).allow(null),
        totalReports: Joi.number().required(),
        numDistinctUsers: Joi.number().required(),
        lastReportedAt: Joi.string().allow('', null),
      }).unknown(true),
    }).unknown(true),
    // Other schemas unchanged
    whois: Joi.object({
      WhoisRecord: Joi.object({
        registrarName: Joi.string().allow('', null),
        createdDate: Joi.string().allow('', null),
        updatedDate: Joi.string().allow('', null),
        expiresDate: Joi.string().allow('', null),
        domainName: Joi.string().allow('', null),
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
          reputation: Joi.number().allow(null),
        }).unknown(true),
      }).unknown(true),
    }).unknown(true),
    shodan: Joi.object({
      ip: Joi.string().required(),
      ports: Joi.array().items(Joi.number()).required(),
      hostnames: Joi.array().items(Joi.string()).allow(null),
      domains: Joi.array().items(Joi.string()).allow(null),
      os: Joi.string().allow('', null),
      isp: Joi.string().allow('', null),
    }).unknown(true),
    threatfox: Joi.object({
      query_status: Joi.string().valid('ok', 'no_result').optional(),
      data: Joi.array().items(Joi.object()).optional().default([]),
    }).unknown(true),
    dns: Joi.object({
      Status: Joi.number().required(),
      Answer: Joi.array()
        .items(
          Joi.object({
            data: Joi.string().required(),
            type: Joi.string().required(),
            TTL: Joi.number().allow(null),
          }),
        )
        .allow(null),
      Question: Joi.array()
        .items(
          Joi.object({
            name: Joi.string().required(),
            type: Joi.number().required(),
          }),
        )
        .allow(null),
    }).unknown(true),
    ssl: Joi.object({
      host: Joi.string().required(),
      port: Joi.number().required(),
      protocol: Joi.string().required(),
      grade: Joi.string().allow('', null),
      serverSignature: Joi.string().allow('', null),
    }).unknown(true),
    asn: Joi.object({
      ip: Joi.string().required(),
      asn: Joi.string().allow(null), // Allow null if ASN cannot be parsed
      org: Joi.string().required(),
    }).unknown(true),
    hybrid: Joi.object({
      result: Joi.object({
        verdict: Joi.string().allow('', null),
        threat_score: Joi.number().allow(null),
        analysis_start_time: Joi.string().allow('', null),
      }).unknown(true),
    }).unknown(true),
    threatcrowd: Joi.object({
      response_code: Joi.string().required(),
      hashes: Joi.array().items(Joi.string()).allow(null),
      ips: Joi.array().items(Joi.string()).allow(null),
    }).unknown(true),
    misp: Joi.object({
      response: Joi.array()
        .items(
          Joi.object({
            Event: Joi.object({
              id: Joi.string().required(),
              info: Joi.string().allow('', null),
              tags: Joi.array().items(Joi.string()).allow(null),
            }).unknown(true),
            Attribute: Joi.object({
              id: Joi.string().required(),
              type: Joi.string().required(),
              value: Joi.string().required(),
            }).unknown(true),
          }).unknown(true),
        )
        .allow(null),
    }).unknown(true),
  },
  enrichmentRegistry: {
    artifact: [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator:
          '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$',
        schema: 'virustotal',
      },
      {
        service: 'hybrid',
        fetchFn: 'fetchHybridAnalysisData',
        field: 'hybrid',
        validator: '^[a-fA-F0-9]{64}$',
        schema: 'hybrid',
      },
    ],
    'autonomous-system': [
      {
        service: 'asn',
        fetchFn: 'fetchASNDataFromNumber',
        field: 'asn',
        validator: '^\\d+$',
      },
    ],
    directory: [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: '.*', // Validates any non-empty string
        schema: 'virustotal',
      },
    ],
    'domain-name': [
      {
        service: 'whois',
        fetchFn: 'fetchWhoisData',
        field: 'whois',
        validator: 'domain-name',
      },
      {
        service: 'dns',
        fetchFn: 'fetchDNSData',
        field: 'dns',
        validator: 'domain-name',
        schema: 'dns',
      },

      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalDomainData',
        field: 'virustotal',
        validator: 'domain-name',
        schema: 'virustotal',
      },
    ],
    'email-address': [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: 'email-address',
        schema: 'virustotal',
      },
    ],
    'email-message': [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: '.*', // Validates any non-empty string
        schema: 'virustotal',
      },
    ],
    file: [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator:
          '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$',
        schema: 'virustotal',
      },
      {
        service: 'threatfox',
        fetchFn: 'fetchThreatFoxData',
        field: 'threatfox',
        validator:
          '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$',
        schema: 'threatfox',
      },
      {
        service: 'hybrid',
        fetchFn: 'fetchHybridAnalysisData',
        field: 'hybrid',
        validator: '^[a-fA-F0-9]{64}$',
        schema: 'hybrid',
      },
    ],
    'ipv4-addr': [
      {
        service: 'geo',
        fetchFn: 'fetchGeoData',
        field: 'geo',
        validator: 'ipv4-addr',
        schema: 'geo',
      },
      {
        service: 'abuseipdb',
        fetchFn: 'fetchAbuseIPDBData',
        field: 'abuseipdb',
        validator: 'ipv4-addr',
        schema: 'abuseipdb',
      },
      {
        service: 'shodan',
        fetchFn: 'fetchShodanData',
        field: 'shodan',
        validator: 'ipv4-addr',
        schema: 'shodan',
      },
      {
        service: 'asn',
        fetchFn: 'fetchASNData',
        field: 'asn',
        validator: 'ipv4-addr',
        schema: 'asn',
      },
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalIpData',
        field: 'virustotal',
        validator: 'ipv4-addr',
        schema: 'virustotal',
      },
    ],
    'ipv6-addr': [
      {
        service: 'geo',
        fetchFn: 'fetchGeoData',
        field: 'geo',
        validator: 'ipv6-addr',
        schema: 'geo',
      },
      {
        service: 'abuseipdb',
        fetchFn: 'fetchAbuseIPDBData',
        field: 'abuseipdb',
        validator: 'ipv6-addr',
        schema: 'abuseipdb',
      },
      {
        service: 'asn',
        fetchFn: 'fetchASNData',
        field: 'asn',
        validator: 'ipv6-addr',
        schema: 'asn',
      },
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalIpData',
        field: 'virustotal',
        validator: 'ipv6-addr',
        schema: 'virustotal',
      },
    ],
    'mac-address': [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: 'mac-address',
        schema: 'virustotal',
      },
    ],
    mutex: [
      {
        service: 'threatcrowd',
        fetchFn: 'fetchThreatCrowdMutexData',
        field: 'threatcrowd',
        validator: '.*', // Validates any non-empty string
        schema: 'threatcrowd',
      },
    ],
    'network-traffic': [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalIpData',
        field: 'virustotal',
        validator: '^(ipv4-addr|ipv6-addr)$', // Custom regex for either IP type
        schema: 'virustotal',
      },
    ],
    process: [
      {
        service: 'hybrid',
        fetchFn: 'fetchHybridAnalysisData',
        field: 'hybrid',
        validator:
          '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$',
        schema: 'hybrid',
      },
    ],
    software: [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: '.*', // Validates any non-empty string
        schema: 'virustotal',
      },
    ],
    url: [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalUrlData',
        field: 'virustotal',
        validator: 'url',
        schema: 'virustotal',
      },
      {
        service: 'dns',
        fetchFn: 'fetchDNSDataFromUrl',
        field: 'dns',
        validator: 'url',
        schema: 'dns',
      },
    ],
    'user-account': [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: '.*', // Validates any non-empty string
        schema: 'virustotal',
      },
    ],
    'windows-registry-key': [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: '^HKEY_.*', // Custom regex for registry keys
        schema: 'virustotal',
      },
    ],
    'x509-certificate': [
      {
        service: 'virustotal',
        fetchFn: 'fetchVirusTotalData',
        field: 'virustotal',
        validator: '^[a-fA-F0-9:]+$', // Validates hex with colons
        schema: 'virustotal',
      },
    ],
    'attack-pattern': [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    campaign: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    'course-of-action': [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    grouping: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    identity: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    incident: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    indicator: [
      {
        service: 'threatfox',
        fetchFn: 'fetchThreatFoxData',
        field: 'threatfox',
        validator: '.*', // Validates any non-empty string
        schema: 'threatfox',
      },
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    infrastructure: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    'intrusion-set': [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    location: [
      {
        service: 'geo',
        fetchFn: 'fetchGeoData',
        field: 'geo',
        validator: '^(ipv4-addr|ipv6-addr)$', // Custom regex for either IP type
        schema: 'geo',
      },
    ],
    malware: [
      {
        service: 'threatfox',
        fetchFn: 'fetchThreatFoxData',
        field: 'threatfox',
        validator: '.*', // Validates any non-empty string
        schema: 'threatfox',
      },
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    'malware-analysis': [
      {
        service: 'hybrid',
        fetchFn: 'fetchHybridAnalysisData',
        field: 'hybrid',
        validator:
          '^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$',
        schema: 'hybrid',
      },
    ],
    note: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    'observed-data': [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    opinion: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    report: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    'threat-actor': [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    tool: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
    vulnerability: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '^CVE-\\d{4}-\\d{4,}$', // Validates CVE format
        schema: 'misp',
      },
    ],
    sighting: [
      {
        service: 'misp',
        fetchFn: 'fetchMispData',
        field: 'misp',
        validator: '.*', // Validates any non-empty string
        schema: 'misp',
      },
    ],
  },
};
