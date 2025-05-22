import {
  CommonProperties,
  PatternType,
} from '../../../core/types/common-data-types';

export type EnrichmentServiceKey =
  | 'geo'
  | 'whois'
  | 'virustotal'
  | 'abuseipdb'
  | 'shodan'
  | 'threatfox'
  | 'dns'
  | 'ssl'
  | 'asn'
  | 'hybrid'
  | 'threatcrowd'
  | 'misp';

export interface ExtensionDefinition {
  id: string;
  type: 'extension-definition';
  spec_version: string;
  name: string;
  description: string;
  created: string;
  modified: string;
  extension_type: 'property-extension';
  version: string;
}

export const ENRICHMENT_EXTENSIONS: Record<
  EnrichmentServiceKey,
  ExtensionDefinition
> = {
  geo: {
    id: 'extension-definition--geo-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'Geo Enrichment',
    description: 'Geolocation enrichment data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  whois: {
    id: 'extension-definition--whois-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'WHOIS Enrichment',
    description: 'WHOIS data for domains',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  virustotal: {
    id: 'extension-definition--virustotal-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'VirusTotal Enrichment',
    description: 'VirusTotal scan results',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  abuseipdb: {
    id: 'extension-definition--abuseipdb-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'AbuseIPDB Enrichment',
    description: 'AbuseIPDB reputation data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  shodan: {
    id: 'extension-definition--shodan-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'Shodan Enrichment',
    description: 'Shodan scan data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  threatfox: {
    id: 'extension-definition--threatfox-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'ThreatFox Enrichment',
    description: 'ThreatFox IOC data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  dns: {
    id: 'extension-definition--dns-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'DNS Enrichment',
    description: 'DNS resolution data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  ssl: {
    id: 'extension-definition--ssl-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'SSL Enrichment',
    description: 'SSL certificate data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  asn: {
    id: 'extension-definition--asn-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'ASN Enrichment',
    description: 'Autonomous System Number data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  hybrid: {
    id: 'extension-definition--hybrid-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'Hybrid Analysis Enrichment',
    description: 'Hybrid Analysis report data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  threatcrowd: {
    id: 'extension-definition--threatcrowd-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'ThreatCrowd Enrichment',
    description: 'ThreatCrowd threat intelligence data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
  misp: {
    id: 'extension-definition--misp-enrichment',
    type: 'extension-definition',
    spec_version: '2.1',
    name: 'MISP Enrichment',
    description: 'MISP threat intelligence data',
    created: '2025-05-03T00:00:00.000Z',
    modified: '2025-05-03T00:00:00.000Z',
    extension_type: 'property-extension',
    version: '1.0',
  },
};

export type StixType =
  | 'artifact'
  | 'autonomous-system'
  | 'directory'
  | 'domain-name'
  | 'email-addr'
  | 'email-message'
  | 'file'
  | 'ipv4-addr'
  | 'ipv6-addr'
  | 'mac-address'
  | 'mutex'
  | 'network-traffic'
  | 'process'
  | 'software'
  | 'url'
  | 'user-account'
  | 'windows-registry-key'
  | 'x509-certificate'
  | 'attack-pattern'
  | 'campaign'
  | 'course-of-action'
  | 'grouping'
  | 'identity'
  | 'incident'
  | 'indicator'
  | 'infrastructure'
  | 'intrusion-set'
  | 'location'
  | 'malware'
  | 'malware-analysis'
  | 'note'
  | 'observed-data'
  | 'opinion'
  | 'report'
  | 'threat-actor'
  | 'tool'
  | 'vulnerability'
  | 'sighting'
  | 'relationship'
  | 'marking-definition';

// Configuration for a generic feed provider
export interface FeedProviderConfig {
  id: string;
  name: string;
  apiUrl: string;
  apiKeyEnv: string;
  headers?: Record<string, string>;
  method?: 'GET' | 'POST';
  params?: Record<string, any>;
  data?: Record<string, any>;
  responsePath?: string;
  batchSize?: number;
  timeout?: number;
  rateLimitDelay?: number;
  maxRetries?: number;
  schedule?: string;
  objectMapper: (
    raw: any,
    config?: FeedProviderConfig,
  ) =>
    | GenericStixObject
    | GenericStixObject[]
    | Generator<GenericStixObject, void, unknown>
    | null;

  pagination?: {
    paramType?: 'params' | 'data';
    pageKey?: string;
    totalCountKey?: string;
    hasNextKey?: string;
    maxPages?: number;
  };
}

export interface EnrichmentData {
  geo?: {
    country_name: string;
    country_code: string;
    city: string;
    lat: number;
    lon: number;
    source?: { service: string; fetched_at: string };
  };
  whois?: {
    domainName: string;
    registrarName: string;
    createdDate: string;
    expiresDate: string;
    source?: { service: string; fetched_at: string };
  };
  virustotal?: {
    data: {
      attributes: {
        last_analysis_stats: {
          malicious: number;
          undetected: number;
          harmless: number;
          suspicious: number;
        };
        reputation: number;
      };
    };
    source?: { service: string; fetched_at: string };
  };
  abuseipdb?: {
    data: {
      abuseConfidenceScore: number;
      countryCode: string;
      totalReports: number;
    };
    source?: { service: string; fetched_at: string };
  };
  shodan?: {
    ip: string;
    org: string;
    os: string | null;
    source?: { service: string; fetched_at: string };
  };
  threatfox?: {
    query_status: string;
    data: {
      threat_type: string;
      malware: string;
    };
    source?: { service: string; fetched_at: string };
  };
  dns?: {
    Status: number;
    Answer: Array<{
      data: string;
      type: string;
      TTL: number;
    }>;
    source?: { source: string; fetched_at: string };
  };
  ssl?: {
    host: string;
    endpoints: Array<{
      serverName: string;
      grade?: string;
      statusMessage?: string;
    }>;
    source?: { service: string; fetched_at: string };
  };
  asn?: {
    ip?: string;
    asn: string;
    org: string;
    source?: { service: string; fetched_at: string };
  };
  hybrid?: {
    result: {
      verdict: string;
      threat_score: number;
      submissions: number;
    };
    source?: { service: string; fetched_at: string };
  };
  threatcrowd?: {
    response_code: string;
    hashes: string[];
    domains: string[];
    source?: { service: string; fetched_at: string };
  };
  misp?: {
    response: {
      Attribute: Array<{
        value: string;
        type: string;
        category: string;
      }>;
    };
    source?: { service: string; fetched_at: string };
  };
}

export interface EnrichmentInput {
  indicator: string;
  type: StixType;
  sourceConfigId?: string;
}

export interface GenericStixObject {
  id: string;
  type: StixType;
  spec_version: string;
  created?: string;
  modified?: string;
  labels?: string[];
  confidence?: number;
  external_references?: Array<{
    source_name: string;
    description?: string;
    url?: string;
    external_id?: string;
  }>;
  object_marking_refs?: string[];
  sourceConfigId?: string;
  extensions?: Record<string, any>;
  indicator?: string;
  value?: string;
  name?: string;
  hashes?: Record<string, string>; // Add type for hashes
  pattern?: string;
  pattern_type?: string;
  [key: string]: any;
}
export interface TLPMarkingDefinition extends GenericStixObject {
  spec_version: '2.1';
  definition_type: 'tlp';
  definition: {
    tlp: 'white' | 'green' | 'amber' | 'red';
  };
  name?: string;
  color?: string;
}
