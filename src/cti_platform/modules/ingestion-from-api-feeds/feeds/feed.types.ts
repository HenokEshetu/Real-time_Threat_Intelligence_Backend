// src/cti_platform/modules/ingestion-from-api-feeds/feeds/feed.types.ts
import { CommonProperties, MarkingDefinition,  } from '../../../core/types/common-data-types';

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
  | 'sighting';

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
  indicatorMapper: (raw: any) => GenericStixObject | null; // Allow null for invalid mappings
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
  actorSophistication?: 'none' | 'minimal' | 'intermediate' | 'advanced' | 'expert' | 'unknown';
  resourceLevel?: 'individual' | 'group' | 'organization' | 'government' | 'unknown';
  malwareCapabilities?: string[];
  architectureExecutionEnvs?: string[];
  relatedIndicators?: string[];
  relatedFiles?: string[];
  indicatorRelationships?: string[];
  relatedThreatActors?: string[];
  validationErrors?: string[]; // Track validation issues (e.g., "invalid TLD")
  enrichment?: EnrichmentData;
  sourceConfigId?: string; // Added to fix TS2339 errors
}

// TLP Marking Definition
export interface TLPMarkingDefinition extends MarkingDefinition {
  definition_type: 'tlp';
  definition: {
    tlp: 'white' | 'green' | 'amber' | 'red';
  };
  name?: string;
  color?: string;
}