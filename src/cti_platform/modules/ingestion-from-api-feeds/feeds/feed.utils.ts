import { parse } from 'tldts';
import { GenericStixObject, StixType } from './feed.types';
import { Logger } from '@nestjs/common';
import {
  MITRE_MAPPING,
  LOCKHEED_MAPPING,
  TYPE_PATTERNS,
  IMPLEMENTATION_LANGUAGES,
  ARCHITECTURES,
  MOTIVATIONS,
  DEFAULT_CONFIDENCE,
  TLP_MARKINGS,
} from './feed.constants';
import { STIXPattern, PatternType, KillChainPhase } from '../../../core/types/common-data-types';
import { v4 as uuidv4 } from 'uuid';
import * as net from 'net';

export class FeedUtils {
  /**
   * Calculates a confidence score (0-100) for an indicator based on multiple factors.
   * Updated to use concise EnrichmentData fields from EnrichmentService.
   */
  static calculateConfidence(indicator: GenericStixObject): number {
    const logger = new Logger('FeedUtils');

    // Assume DEFAULT_CONFIDENCE is 90; adjust in feed.constants if needed
    let confidence = DEFAULT_CONFIDENCE;
    const contributions: Record<string, number> = { base: DEFAULT_CONFIDENCE };

    // Basic checks
    if (indicator.validated === true) {
      confidence += 5;
      contributions.validated = 5;
    }

    if (Array.isArray(indicator.references) && indicator.references.length > 0) {
      const refScore = Math.min(indicator.references.length * 2, 10);
      confidence += refScore;
      contributions.references = refScore;
    }

    // Simplified enrichment checks
    if (indicator.enrichment && typeof indicator.enrichment === 'object') {
      const vtStats = indicator.enrichment.virustotal?.data?.attributes?.last_analysis_stats;
      if (vtStats && typeof vtStats === 'object') {
        const totalScans = (vtStats.malicious || 0) + (vtStats.undetected || 0) + (vtStats.harmless || 0) + (vtStats.suspicious || 0);
        const detectionRate = totalScans > 0 ? vtStats.malicious / totalScans : 0;
        const vtScore = Math.round(detectionRate * 20);
        confidence += vtScore;
        contributions.virustotal = vtScore;
      }

      if (indicator.enrichment.abuseipdb?.data?.totalReports > 0) {
        const abuseScore = Math.min(Math.floor(indicator.enrichment.abuseipdb.data.totalReports / 5), 10);
        confidence += abuseScore;
        contributions.abuseipdb = abuseScore;
      }

      if (indicator.enrichment.threatfox?.data?.malware) {
        confidence += 5;
        contributions.threatfox = 5;
      }
    } else {
      confidence -= 5;
      contributions.noEnrichment = -5;
    }

    // Age check
    if (indicator.created && typeof indicator.created === 'string') {
      try {
        const createdDate = new Date(indicator.created);
        if (isNaN(createdDate.getTime())) throw new Error('Invalid date');
        const ageDays = (Date.now() - createdDate.getTime()) / (1000 * 60 * 60 * 24);
        if (ageDays < 7) {
          confidence += 5;
          contributions.recent = 5;
        } else if (ageDays > 30) {
          const penalty = Math.min(Math.floor(ageDays / 30) * 5, 15);
          confidence -= penalty;
          contributions.agePenalty = -penalty;
        }
      } catch (error) {
        logger.warn('Invalid created date', { created: indicator.created, error: error.message });
      }
    }

    // Final score
    const finalConfidence = Math.max(0, Math.min(confidence, 100));
    return finalConfidence;
  }

  /**
   * Determines kill chain phases using concise EnrichmentData.
   */
  static determineKillChainPhases(indicator: GenericStixObject): KillChainPhase[] {
    const phases: KillChainPhase[] = [];
    const desc = (indicator.description || '').toLowerCase();
    const type = (indicator.type || '').toLowerCase().replace('filehash-', 'file');

    const addPhase = (killChain: string, phase: string) => {
      phases.push({ kill_chain_name: killChain, phase_name: phase, id: uuidv4() });
    };

    MITRE_MAPPING.forEach(mapping => {
      if (mapping.condition(desc, type)) addPhase('mitre-attack', mapping.phase);
    });

    LOCKHEED_MAPPING.forEach(mapping => {
      if (mapping.condition(type, desc)) addPhase('lockheed-martin-cyber-kill-chain', mapping.phase);
    });

    // Updated for concise enrichment data
    if (indicator.enrichment?.virustotal?.data?.attributes?.last_analysis_stats?.malicious > 0) {
      addPhase('mitre-attack', 'execution');
    }
    if (indicator.enrichment?.dns?.Answer?.length) {
      addPhase('mitre-attack', 'command-and-control');
    }
    if (indicator.enrichment?.abuseipdb?.data?.totalReports > 10) {
      addPhase('lockheed-martin-cyber-kill-chain', 'actions-on-objectives');
    }
    if (indicator.enrichment?.hybrid?.result?.verdict === 'malicious') {
      addPhase('mitre-attack', 'execution');
    }
    if (indicator.enrichment?.threatcrowd?.domains?.length) {
      addPhase('mitre-attack', 'command-and-control'); // Domains suggest C2
    }
    if (indicator.enrichment?.misp?.response?.Attribute?.some(a => a.category === 'malware')) {
      addPhase('mitre-attack', 'execution');
    }

    return [...new Set(phases.map(p => `${p.kill_chain_name}:${p.phase_name}`))].map((unique, idx) => ({
      kill_chain_name: unique.split(':')[0],
      phase_name: unique.split(':')[1],
      id: phases[idx].id,
    }));
  }

  static identifyStixType(obj: GenericStixObject): StixType {
    const logger = new Logger('FeedUtils');

    // Hash patterns for file indicators
    const hashPatterns = {
      md5: /^[a-fA-F0-9]{32}$/,
      sha1: /^[a-fA-F0-9]{40}$/,
      sha256: /^[a-fA-F0-9]{64}$/,
      sha512: /^[a-fA-F0-9]{128}$/,
    };

    // Validate hashes for file indicators
    if (obj.hashes && Object.keys(obj.hashes).length > 0) {
      const validHash = Object.values(obj.hashes).every(hash =>
        hashPatterns.md5.test(hash) ||
        hashPatterns.sha1.test(hash) ||
        hashPatterns.sha256.test(hash) ||
        hashPatterns.sha512.test(hash)
      );
      return validHash ? 'file' : 'indicator';
    }

    // Validate value-based indicators
    if (obj.value) {
      // Hash check for raw values
      if (
        hashPatterns.md5.test(obj.value) ||
        hashPatterns.sha1.test(obj.value) ||
        hashPatterns.sha256.test(obj.value) ||
        hashPatterns.sha512.test(obj.value)
      ) {
        return 'file';
      }

      // Domain: Use tldts for robust validation
      const parsed = parse(obj.value);
      if (parsed.domain && parsed.publicSuffix && !obj.value.includes(' ')) {
        return 'domain-name';
      }

      // URL: Require protocol and path/query
      const urlPattern = /^(https?:\/\/)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/;
      if (
        urlPattern.test(obj.value) ||
        (TYPE_PATTERNS.url.test(obj.value) && /^(https?:\/\/)/.test(obj.value)) ||
        (obj.value.includes('/') && obj.value.includes('?'))
      ) {
        return 'url';
      }

      // IP addresses
      if (net.isIP(obj.value)) {
        return net.isIPv6(obj.value) ? 'ipv6-addr' : 'ipv4-addr';
      }
      if (TYPE_PATTERNS['ipv6-addr'].test(obj.value)) {
        return 'ipv6-addr';
      }

      // MAC address
      if (TYPE_PATTERNS['mac-address'].test(obj.value)) {
        return 'mac-address';
      }

      // Email address
      if (TYPE_PATTERNS['email-address'].test(obj.value)) {
        return 'email-addr';
      }
    }

    // Validate indicator field
    if (obj.indicator) {
      // Hash check for raw indicators
      if (
        hashPatterns.md5.test(obj.indicator) ||
        hashPatterns.sha1.test(obj.indicator) ||
        hashPatterns.sha256.test(obj.indicator) ||
        hashPatterns.sha512.test(obj.indicator)
      ) {
        return 'file';
      }

      // Domain: Use tldts to validate
      const parsed = parse(obj.indicator);
      if (parsed.domain && parsed.publicSuffix && !obj.indicator.includes(' ')) {
        return 'domain-name';
      }

      // URL: Require protocol and path/query
      const urlPattern = /^(https?:\/\/)[a-zA-F0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/;
      if (
        urlPattern.test(obj.indicator) ||
        (TYPE_PATTERNS.url.test(obj.indicator) && /^(https?:\/\/)/.test(obj.indicator)) ||
        (obj.indicator.includes('/') && obj.indicator.includes('?'))
      ) {
        return 'url';
      }

      // IP addresses
      if (TYPE_PATTERNS['ipv4-addr'].test(obj.indicator)) {
        return 'ipv4-addr';
      }
      if (TYPE_PATTERNS['ipv6-addr'].test(obj.indicator)) {
        return 'ipv6-addr';
      }

      // Email address
      if (TYPE_PATTERNS['email-address'].test(obj.indicator)) {
        return 'email-addr';
      }

      // MAC address
      if (TYPE_PATTERNS['mac-address'].test(obj.indicator)) {
        return 'mac-address';
      }

      return 'indicator';
    }

    // Named objects (malware, threat-actor, etc.)
    if (obj.name) {
      if (obj.labels?.includes('malicious') || obj.malwareTypes?.length) {
        return 'malware';
      }
      if (obj.threatActorTypes?.length || obj.roles?.length) {
        return 'threat-actor';
      }
      if (obj.labels?.includes('campaign')) {
        return 'campaign';
      }
      if (obj.labels?.includes('tool')) {
        return 'tool';
      }
    }

    // Fallback to provided type or 'observed-data'
    return obj.type || 'observed-data';
  }

  /**
   * Validates if a type is a valid STIX 2.1 type.
   */
  static isValidStixType(type: string): boolean {
    const validTypes: StixType[] = [
      'artifact', 'autonomous-system', 'directory', 'domain-name', 'email-addr', 'email-message', 'file',
      'ipv4-addr', 'ipv6-addr', 'mac-address', 'mutex', 'network-traffic', 'process', 'software', 'url',
      'user-account', 'windows-registry-key', 'x509-certificate', 'attack-pattern', 'campaign',
      'course-of-action', 'grouping', 'identity', 'incident', 'indicator', 'infrastructure', 'intrusion-set',
      'location', 'malware', 'malware-analysis', 'note', 'observed-data', 'opinion', 'report', 'threat-actor',
      'tool', 'vulnerability', 'sighting'
    ];
    return validTypes.includes(type as StixType);
  }

  /**
   * Builds a detailed description using concise EnrichmentData.
   */
  static buildDescription(indicator: GenericStixObject): string {
    const parts: string[] = [
      `**Indicator Type:** ${indicator.type || 'Unknown'}`,
      `**Value:** ${indicator.indicator || indicator.value || indicator.name || Object.values(indicator.hashes || {})[0] || 'N/A'}`,
      `**Confidence:** ${FeedUtils.calculateConfidence(indicator)}`,
    ];

    if (indicator.description) parts.push(`**Description:**\n${indicator.description}`);
    if (indicator.labels?.length) parts.push(`**Labels:** ${indicator.labels.join(', ')}`);

    if (indicator.enrichment) {
      const enrichmentParts: string[] = [];
      if (indicator.enrichment.geo?.country_name) {
        enrichmentParts.push(
          `- **Geolocation:** ${indicator.enrichment.geo.country_name} (${indicator.enrichment.geo.country_code}), City: ${indicator.enrichment.geo.city || 'N/A'}`,
        );
      }
      if (indicator.enrichment.whois?.domainName) {
        enrichmentParts.push(
          `- **Whois:** Domain: ${indicator.enrichment.whois.domainName}, Registrar: ${indicator.enrichment.whois.registrarName || 'N/A'}, Created: ${indicator.enrichment.whois.createdDate || 'N/A'}`,
        );
      }
      if (indicator.enrichment.virustotal?.data?.attributes?.last_analysis_stats) {
        const stats = indicator.enrichment.virustotal.data.attributes.last_analysis_stats;
        const total = stats.malicious + stats.undetected + stats.harmless + stats.suspicious;
        enrichmentParts.push(
          `- **VirusTotal:** ${stats.malicious}/${total} malicious scans, Reputation: ${indicator.enrichment.virustotal.data.attributes.reputation || 'N/A'}`,
        );
      }
      if (indicator.enrichment.abuseipdb?.data) {
        enrichmentParts.push(
          `- **AbuseIPDB:** ${indicator.enrichment.abuseipdb.data.totalReports || 0} reports, Score: ${indicator.enrichment.abuseipdb.data.abuseConfidenceScore || 'N/A'}`,
        );
      }
      if (indicator.enrichment.shodan?.ip) {
        enrichmentParts.push(
          `- **Shodan:** IP: ${indicator.enrichment.shodan.ip}, Org: ${indicator.enrichment.shodan.org || 'N/A'}, OS: ${indicator.enrichment.shodan.os || 'N/A'}`,
        );
      }
      if (indicator.enrichment.threatfox?.data) {
        enrichmentParts.push(
          `- **ThreatFox:** Type: ${indicator.enrichment.threatfox.data.threat_type || 'N/A'}, Malware: ${indicator.enrichment.threatfox.data.malware || 'N/A'}`,
        );
      }
      if (indicator.enrichment.dns?.Answer?.length) {
        enrichmentParts.push(
          `- **DNS:** ${indicator.enrichment.dns.Answer.map(a => `${a.type}: ${a.data} (TTL: ${a.TTL})`).join(', ')}`,
        );
      }
      if (indicator.enrichment.ssl?.endpoints?.length) {
        enrichmentParts.push(
          `- **SSL:** Grade: ${indicator.enrichment.ssl.endpoints[0].grade || 'N/A'}, Server: ${indicator.enrichment.ssl.endpoints[0].serverName || 'N/A'}`,
        );
      }
      if (indicator.enrichment.asn?.asn) {
        enrichmentParts.push(
          `- **ASN:** ${indicator.enrichment.asn.asn} (${indicator.enrichment.asn.org || 'Unknown'})`,
        );
      }
      if (indicator.enrichment.hybrid?.result) {
        enrichmentParts.push(
          `- **Hybrid Analysis:** Verdict: ${indicator.enrichment.hybrid.result.verdict || 'N/A'}, Score: ${indicator.enrichment.hybrid.result.threat_score || 'N/A'}, Submissions: ${indicator.enrichment.hybrid.result.submissions || 0}`,
        );
      }
      if (indicator.enrichment.threatcrowd?.hashes?.length || indicator.enrichment.threatcrowd?.domains?.length) {
        enrichmentParts.push(
          `- **ThreatCrowd:** Hashes: ${indicator.enrichment.threatcrowd.hashes?.length || 0}, Domains: ${indicator.enrichment.threatcrowd.domains?.length || 0}`,
        );
      }
      if (indicator.enrichment.misp?.response?.Attribute?.length) {
        enrichmentParts.push(
          `- **MISP:** Attributes: ${indicator.enrichment.misp.response.Attribute.length}, First: ${indicator.enrichment.misp.response.Attribute[0]?.type || 'N/A'} (${indicator.enrichment.misp.response.Attribute[0]?.value || 'N/A'})`,
        );
      }
      if (enrichmentParts.length) parts.push(`**Enrichment Data:**\n${enrichmentParts.join('\n')}`);
    }

    if (indicator.references?.length) parts.push(`**References:**\n- ${indicator.references.join('\n- ')}`);
    if (indicator.relatedIndicators?.length) parts.push(`**Related Indicators:** ${indicator.relatedIndicators.join(', ')}`);

    return parts.join('\n\n');
  }

  /**
   * Creates STIX pattern using concise EnrichmentData.
   */
  static createStixPattern(indicator: GenericStixObject): STIXPattern {
    let primaryValue = indicator.indicator || indicator.value || indicator.name || Object.values(indicator.hashes || {})[0];
    if (!primaryValue) {
      // Fallback: use 'unknown' and log a warning instead of throwing an error
      primaryValue = 'unknown';
      new Logger('FeedUtils').warn(`Primary value missing in STIX pattern creation, falling back to 'unknown'`, { indicator });
    }

    const now = new Date().toISOString();
    const oneYearLater = new Date(new Date().setFullYear(new Date().getFullYear() + 1)).toISOString();
    const escapeValue = (val: string) =>
      val.replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\[/g, '\\[').replace(/\]/g, '\\]');
    const stixType = this.identifyStixType(indicator);
    let patternKey = this.getPatternKey(stixType);
    let pattern;

    // Handle file hashes
    if (stixType === 'file') {
      const hashPatterns = {
        md5: /^[a-fA-F0-9]{32}$/,
        sha1: /^[a-fA-F0-9]{40}$/,
        sha256: /^[a-fA-F0-9]{64}$/,
        sha512: /^[a-fA-F0-9]{128}$/,
      };
      let hashType = 'MD5';
      if (hashPatterns.sha1.test(primaryValue)) hashType = 'SHA-1';
      else if (hashPatterns.sha256.test(primaryValue)) hashType = 'SHA-256';
      else if (hashPatterns.sha512.test(primaryValue)) hashType = 'SHA-512';
      pattern = `[file:hashes.'${hashType}' = '${escapeValue(primaryValue)}']`;
    } else {
      pattern = `[${patternKey} = '${escapeValue(primaryValue)}']`;
    }

    // Add enrichment-based conditions
    if (stixType === 'domain-name' && indicator.enrichment?.dns?.Answer?.length) {
      const dnsValues = indicator.enrichment.dns.Answer.map(a => escapeValue(a.data));
      pattern += ` AND [domain-name:resolves_to_refs.value IN (${dnsValues.map(v => `'${v}'`).join(', ')})]`;
    }
    if ((stixType === 'ipv4-addr' || stixType === 'ipv6-addr') && indicator.enrichment?.asn?.asn) {
      pattern += ` AND [autonomous-system:number = '${escapeValue(indicator.enrichment.asn.asn)}']`;
    }
    if (stixType === 'malware' && indicator.enrichment?.misp?.response?.Attribute?.length) {
      const mispTypes = indicator.enrichment.misp.response.Attribute.filter(a => a.category === 'malware').map(a => escapeValue(a.type));
      if (mispTypes.length) pattern += ` AND [malware:labels IN (${mispTypes.map(t => `'${t}'`).join(', ')})]`;
    }

    return {
      pattern,
      pattern_type: 'stix' as PatternType,
      pattern_version: '2.1',
      valid_from: indicator.created || now,
      valid_until: indicator.expiration || oneYearLater,
    };
  }

  /**
   * Maps STIX types to pattern keys with full STIX 2.1 support.
   */
  private static getPatternKey(stixType: StixType): string {
    const patternKeys: Record<StixType, string> = {
      'artifact': 'artifact:content',
      'autonomous-system': 'autonomous-system:number',
      'directory': 'directory:path',
      'domain-name': 'domain-name:value',
      'email-addr': 'email-addr:value',
      'email-message': 'email-message:subject',
      'file': 'file:hashes', // Default, refined in pattern if needed
      'ipv4-addr': 'ipv4-addr:value',
      'ipv6-addr': 'ipv6-addr:value',
      'mac-address': 'mac-addr:value',
      'mutex': 'mutex:name',
      'network-traffic': 'network-traffic:dst_ref.value',
      'process': 'process:pid',
      'software': 'software:name',
      'url': 'url:value',
      'user-account': 'user-account:account_login',
      'windows-registry-key': 'windows-registry-key:key',
      'x509-certificate': 'x509-certificate:serial_number',
      'attack-pattern': 'attack-pattern:name',
      'campaign': 'campaign:name',
      'course-of-action': 'course-of-action:name',
      'grouping': 'grouping:name',
      'identity': 'identity:name',
      'incident': 'incident:name',
      'indicator': 'indicator:pattern',
      'infrastructure': 'infrastructure:name',
      'intrusion-set': 'intrusion-set:name',
      'location': 'location:name',
      'malware': 'malware:name',
      'malware-analysis': 'malware-analysis:product',
      'note': 'note:content',
      'observed-data': 'observed-data:first_observed',
      'opinion': 'opinion:explanation',
      'report': 'report:name',
      'threat-actor': 'threat-actor:name',
      'tool': 'tool:name',
      'vulnerability': 'vulnerability:name',
      'sighting': 'sighting:summary',
      'relationship': '',
    };
    return patternKeys[stixType] || 'indicator:pattern';
  }

  /**
   * Infers implementation languages with more robust matching.
   */
  static inferImplementationLanguages(description?: string): string[] {
    if (!description) return [];
    const desc = description.toLowerCase();
    return IMPLEMENTATION_LANGUAGES.filter(lang => {
      const aliases: Record<string, string[]> = {
        javascript: ['js', 'node.js'],
        'c#': ['c sharp', 'csharp'],
        golang: ['go', 'go lang'],
        python: ['py'],
      };
      return desc.includes(lang) || (aliases[lang] && aliases[lang].some(alias => desc.includes(alias)));
    });
  }

  /**
   * Infers architectures with additional aliases.
   */
  static inferArchitectures(description?: string): string[] {
    if (!description) return [];
    const desc = description.toLowerCase();
    const aliases: Record<string, string[]> = {
      x86_64: ['x64', '64-bit'],
      x86: ['32-bit'],
      arm: ['arm64'],
    };
    return ARCHITECTURES.filter(arch =>
      desc.includes(arch) || (aliases[arch] && aliases[arch].some(alias => desc.includes(alias))),
    );
  }

  /**
   * Infers primary motivation with broader keyword matching.
   */
  static inferPrimaryMotivation(description?: string): string {
    if (!description) return 'unknown';
    const desc = description.toLowerCase();
    const motivationKeywords: Record<string, string[]> = {
      'financial-gain': ['financial', 'profit', 'extortion', 'ransom', 'money'],
      espionage: ['espionage', 'intelligence', 'spying', 'data theft'],
      ideology: ['ideology', 'belief', 'cause', 'activism'],
      destruction: ['destruction', 'damage', 'disrupt', 'sabotage'],
      political: ['political', 'government', 'election'],
      competitive: ['competition', 'rival', 'market'],
      revenge: ['revenge', 'retaliation', 'vendetta'],
    };

    for (const [motivation, keywords] of Object.entries(motivationKeywords)) {
      if (keywords.some(keyword => desc.includes(keyword))) return motivation;
    }
    return 'unknown';
  }

  /**
   * Infers secondary motivations with keyword matching.
   */
  static inferSecondaryMotivations(description?: string): string[] {
    if (!description) return [];
    const desc = description.toLowerCase();
    const motivationKeywords: Record<string, string[]> = {
      'reputation-gain': ['reputation', 'fame', 'notoriety'],
      destruction: ['destruction', 'damage', 'disrupt'],
      ideology: ['ideology', 'belief', 'cause'],
      'attention-seeking': ['attention', 'publicity', 'notice'],
      fear: ['fear', 'intimidation', 'threat'],
      revenge: ['revenge', 'retaliation', 'vendetta'],
      disruption: ['disruption', 'chaos', 'downtime'],
      'social-impact': ['social', 'community', 'change'],
      competitive: ['competition', 'rival', 'edge'],
      'financial-pressure': ['financial', 'pressure', 'debt'],
    };

    return MOTIVATIONS.SECONDARY.filter(motivation =>
      motivationKeywords[motivation]?.some(keyword => desc.includes(keyword)),
    );
  }

  /**
   * Determines TLP level with fallback logic.
   */
  static determineTLPLevel(indicator: GenericStixObject): keyof typeof TLP_MARKINGS {
    const sensitivity = indicator.sensitivity?.toLowerCase() || 'medium';
    const sharing = indicator.sharing?.toLowerCase() || 'community';

    const tlpMap: Record<string, keyof typeof TLP_MARKINGS> = {
      critical: 'RED',
      high: 'AMBER',
      medium: 'GREEN',
      low: 'WHITE',
    };
    const sharingMap: Record<string, keyof typeof TLP_MARKINGS> = {
      restricted: 'RED',
      limited: 'AMBER',
      community: 'GREEN',
      public: 'WHITE',
    };

    return tlpMap[sensitivity] || sharingMap[sharing] || 'GREEN'; // Default to GREEN
  }
}