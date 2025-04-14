import { CommonProperties, MarkingDefinition, MarkingDefinitionType } from '../../../core/types/common-data-types';

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
  indicatorMapper: (raw: any) => GenericStixObject;
}

// Enrichment data structure (unchanged)
export interface EnrichmentData {
  geo?: {
    country_name: string;
    country_code?: string;
    lat?: number;
    lon?: number;
    city?: string;
  };
  whois?: {
    WhoisRecord?: {
      registrarName?: string;
      createdDate?: string;
      updatedDate?: string;
      expiresDate?: string;
      nameServers?: string[];
    };
  };
  virustotal?: {
    data?: {
      id?: string;
      attributes?: {
        last_analysis_stats?: {
          malicious: number;
          undetected?: number;
          total?: number;
          harmless?: number;
          suspicious?: number;
        };
        names?: string[];
        reputation?: number;
        last_analysis_date?: string;
      };
    };
  };
  abuseipdb?: {
    data?: {
      totalReports?: number;
      abuseConfidenceScore?: number;
      lastReportedAt?: string;
      isp?: string;
    };
  };
  shodan?: {
    hostnames?: string[];
    ports?: number[];
    os?: string;
    last_update?: string;
  };
  threatfox?: {
    data?: Array<{
      ioc_value: string;
      ioc_type: string;
      malware: string;
      confidence_level?: number;
      first_seen?: string;
    }>;
  };
  dns?: {
    Answer?: Array<{
      data: string;
      type: string;
      TTL?: number;
    }>;
    Question?: Array<{ name: string; type: number }>;
  };
  ssl?: {
    endpoints?: Array<{
      grade?: string;
      ipAddress?: string;
      protocols?: Array<{ name: string; version: string }>;
      details?: { heartbleed?: boolean; poodle?: boolean };
    }>;
  };
  asn?: {
    asn?: string;
    org?: string;
    routes?: string[];
  };
  hybrid?: {
    summary?: {
      environment?: string;
      threat_score?: number;
      verdict?: string;
      analysis_time?: string;
    };
    hashes?: { md5?: string; sha1?: string; sha256?: string; sha512?: string };
  };
  threatcrowd?: {
    hashes?: string[];
    ips?: string[];
    domains?: string[];
    last_seen?: string;
  };
  misp?: {
    events?: Array<{
      Event?: {
        info?: string;
        tags?: string[];
        timestamp?: string;
        attributes?: Array<{ type: string; value: string }>;
      };
    }>;
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

  // STIX-specific fields
  hashes?: Record<string, string>; // For 'file' (e.g., { 'SHA-256': '...', 'MD5': '...' })
  malwareTypes?: string[]; // For 'malware'
  threatActorTypes?: string[]; // For 'threat-actor'
  aliases?: string[];
  roles?: string[];
  actorSophistication?: 'none' | 'minimal' | 'intermediate' | 'advanced' | 'expert' | 'unknown';
  resourceLevel?: 'individual' | 'group' | 'organization' | 'government' | 'unknown';
  malwareCapabilities?: string[];
  architectureExecutionEnvs?: string[];

  // Relationships to other STIX objects
  relatedIndicators?: string[];
  relatedFiles?: string[];
  indicatorRelationships?: string[];
  relatedThreatActors?: string[];

  // Enrichment data
  enrichment?: EnrichmentData;
}

// TLP Marking Definition (unchanged)
export interface TLPMarkingDefinition extends MarkingDefinition {
  definition_type: 'tlp';
  definition: {
    tlp: 'white' | 'green' | 'amber' | 'red';
  };
  name?: string;
  color?: string;
}