// src/cti_platform/modules/ingestion-from-api-feeds/feeds/feed.types.ts
import {
  CommonProperties,
  MarkingDefinition,
} from '../../../core/types/common-data-types';

// STIX 2.1 object types supported by the project (verified complete per STIX 2.1 spec)
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
  | 'relationship';

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
  indicatorMapper: (raw: any) => GenericStixObject | GenericStixObject[] | null; // Allow array or null
  pagination?: {
    paramType?: 'params' | 'data'; // Where to apply pagination parameters (query params or request body)
    pageKey?: string; // Key for page number (e.g., 'page', 'offset', 'cursor')
    totalCountKey?: string; // Key for total item count in response (e.g., 'total_count')
    hasNextKey?: string; // Key for next-page indicator (e.g., 'has_next')
    maxPages?: number; // Maximum pages to fetch (default: 100)
  };
}

// Enrichment data structure aligned with EnrichmentService's conciseResponseFields
export interface EnrichmentData {
  geo?: {
    country_name: string;
    country_code: string;
    city: string;
    lat: number;
    lon: number;
  };
  whois?: {
    domainName: string;
    registrarName: string;
    createdDate: string;
    expiresDate: string;
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
  };
  abuseipdb?: {
    data: {
      abuseConfidenceScore: number;
      countryCode: string;
      totalReports: number;
    };
  };
  shodan?: {
    ip: string;
    org: string;
    os: string | null;
  };
  threatfox?: {
    query_status: string;
    data: {
      threat_type: string;
      malware: string;
    };
  };
  dns?: {
    Answer: Array<{
      data: string;
      type: string;
      TTL: number;
    }>;
  };
  ssl?: {
    host: string;
    endpoints: Array<{
      serverName: string;
      grade: string;
    }>;
  };
  asn?: {
    asn: string;
    org: string;
    ip?: string;
  };
  hybrid?: {
    result: {
      verdict: string;
      threat_score: number;
      submissions: number;
    };
  };
  threatcrowd?: {
    response_code: string;
    hashes: string[];
    domains: string[];
  };
  misp?: {
    response: {
      Attribute: Array<{
        value: string;
        type: string;
        category: string;
      }>;
    };
  };
}

// Generic indicator structure (updated for STIX 2.1 compliance)
export interface GenericStixObject extends Partial<CommonProperties> {
  id?: string; // Provider-specific ID (optional)
  indicator?: string; // Optional IOC value (e.g., for 'indicator' type)
  type: StixType; // STIX 2.1 type
  value?: string; // For SCOs like 'url', 'domain-name', 'ipv4-addr'
  name?: string; // For SDOs like 'malware', 'threat-actor'
  description?: string;
  created?: string;
  modified?: string;
  valid_from?: string;
  expiration?: string;
  validated?: boolean;
  reputation?: number;
  references?: string[];
  labels?: string[];
  sensitivity?: 'low' | 'medium' | 'high' | 'critical';
  sharing?: 'public' | 'community' | 'limited' | 'restricted';
  hashes?: Record<'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512', string>; // Restrict hash types
  malwareTypes?: string[]; // For 'malware'
  threatActorTypes?: string[]; // For 'threat-actor'
  aliases?: string[];
  roles?: string[];
  actorSophistication?:
    | 'none'
    | 'minimal'
    | 'intermediate'
    | 'advanced'
    | 'expert'
    | 'unknown';
  resourceLevel?:
    | 'individual'
    | 'group'
    | 'organization'
    | 'government'
    | 'unknown';
  malwareCapabilities?: string[];
  architectureExecutionEnvs?: string[];
  relatedIndicators?: string[];
  relatedFiles?: string[];
  indicatorRelationships?: string[];
  relatedThreatActors?: string[];
  validationErrors?: string[]; // Track validation issues (e.g., "invalid TLD")
  enrichment?: EnrichmentData;
  sourceConfigId?: string; // Added to fix TS2339 errors
  // --- Added for STIX compatibility ---
  published?: string; // For 'report'
  report_types?: string[]; // For 'report'
  pattern?: string; // For 'indicator'
  pattern_type?: string; // For 'indicator'
  resolves_to_refs?: string[]; // For 'domain-name'
  number?: number; // For 'autonomous-system'
  malware_types?: string[]; // For 'malware' (legacy, mapped to malwareTypes)
  threat_actor_types?: string[]; // For 'threat-actor' (legacy, mapped to threatActorTypes)
  dst_ref?: string; // For 'network-traffic'
  dst_port?: number; // For 'network-traffic'
  key?: string; // For 'windows-registry-key'
  values?: any[]; // For 'windows-registry-key'
  account_login?: string; // For 'user-account'
  account_type?: string; // For 'user-account'
  identity_class?: string; // For 'identity'
  infrastructure_types?: string[]; // For 'infrastructure'
  payload_bin?: string; // For 'artifact'
  content?: string; // For 'note'
  arguments?: string[]; // For 'process'
  first_observed?: string; // For 'observed-data'
  last_observed?: string; // For 'observed-data'
  object_refs?: string[]; // For 'observed-data'
  number_observed?: number; // For observed-data
  // --- Added for relationships ---
  source_ref?: string;
  target_ref?: string;
  relationship_type?: string;
}

// TLP Marking Definition
export interface TLPMarkingDefinition extends MarkingDefinition {
  // Added property to allow spec_version
  spec_version: string;
  definition_type: 'tlp';
  definition: {
    tlp: 'white' | 'green' | 'amber' | 'red';
  };
  name?: string;
  color?: string;
}
