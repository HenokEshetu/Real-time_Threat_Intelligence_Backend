import { GenericStixObject, StixType } from './feed.types';
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

export class FeedUtils {
  /**
   * Calculates a confidence score (0-100) for an indicator based on multiple factors.
   * Enhanced with new enrichment sources (hybrid, threatcrowd, misp) and SHA-512 support.
   */
  static calculateConfidence(indicator: GenericStixObject): number {
    let confidence = DEFAULT_CONFIDENCE;

    if (indicator.validated) confidence += 5;
    if (indicator.references?.length) confidence += Math.min(indicator.references.length * 2, 10);

    const vtStats = indicator.enrichment?.virustotal?.data?.attributes?.last_analysis_stats;
    if (vtStats) {
      const totalScans = vtStats.malicious + (vtStats.undetected ?? 0) + (vtStats.total ?? 0);
      const detectionRate = totalScans > 0 ? vtStats.malicious / totalScans : 0;
      confidence += Math.round(detectionRate * 20);
    }

    if (indicator.enrichment?.abuseipdb?.data?.totalReports) {
      confidence += Math.min(Math.floor(indicator.enrichment.abuseipdb.data.totalReports / 5), 15);
    }

    if (indicator.enrichment?.threatfox?.data?.length) {
      confidence += Math.min(indicator.enrichment.threatfox.data.length * 3, 10);
    }

    if (indicator.enrichment?.hybrid?.summary?.threat_score) {
      confidence += Math.min(Math.floor(indicator.enrichment.hybrid.summary.threat_score / 10), 15);
    }

    if (indicator.enrichment?.threatcrowd?.hashes?.length) {
      confidence += Math.min(indicator.enrichment.threatcrowd.hashes.length * 2, 10);
    }

    if (indicator.enrichment?.misp?.events?.length) {
      confidence += Math.min(indicator.enrichment.misp.events.length * 3, 12);
    }

    if (indicator.reputation) {
      confidence += Math.min(Math.floor(indicator.reputation / 10), 10);
    }

    if (indicator.created) {
      const ageDays = (Date.now() - new Date(indicator.created).getTime()) / (1000 * 60 * 60 * 24);
      if (ageDays < 7) confidence += 5; // Fresher data boost
      else if (ageDays > 90) confidence -= Math.min(Math.floor(ageDays / 30) * 3, 20); // Slower decay
    }

    return Math.max(0, Math.min(confidence, 100));
  }

  /**
   * Determines kill chain phases with improved logic using new enrichment data.
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

    // Enhanced with new enrichment data
    if (indicator.enrichment?.virustotal?.data?.attributes?.last_analysis_stats?.malicious > 0) {
      addPhase('mitre-attack', 'execution');
    }
    if (indicator.enrichment?.dns?.Answer?.length) {
      addPhase('mitre-attack', 'command-and-control');
    }
    if (indicator.enrichment?.abuseipdb?.data?.totalReports > 10) {
      addPhase('lockheed-martin-cyber-kill-chain', 'actions-on-objectives');
    }
    if (indicator.enrichment?.hybrid?.summary?.verdict === 'malicious') {
      addPhase('mitre-attack', 'execution'); // Malware execution
    }
    if (indicator.enrichment?.threatcrowd?.ips?.length) {
      addPhase('mitre-attack', 'lateral-movement'); // IP-based lateral movement
    }
    if (indicator.enrichment?.misp?.events?.some(e => e.Event?.tags?.includes('malware'))) {
      addPhase('mitre-attack', 'execution'); // MISP malware tag
    }

    return [...new Set(phases.map(p => `${p.kill_chain_name}:${p.phase_name}`))].map((unique, idx) => ({
      kill_chain_name: unique.split(':')[0],
      phase_name: unique.split(':')[1],
      id: phases[idx].id,
    }));
  }

  /**
   * Identifies STIX type with improved logic for all STIX 2.1 types.
   */
  static identifyStixType(obj: GenericStixObject): StixType {
    // Check STIX-specific fields first
    if (obj.hashes && Object.keys(obj.hashes).length > 0) return 'file';
    if (obj.value) {
      if (obj.value.match(/^https?:\/\//)) return 'url';
      if (obj.value.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/) && !obj.value.includes('/')) return 'domain-name';
      if (obj.value.match(/^\d+\.\d+\.\d+\.\d+$/)) return 'ipv4-addr';
      if (obj.value.match(/^[0-9a-f:]+$/i) && obj.value.includes(':')) return 'ipv6-addr';
      if (obj.value.match(/^[a-f0-9]{2}(:[a-f0-9]{2}){5}$/i)) return 'mac-address';
      if (obj.value.match(/^[^@]+@[^@]+\.[^@]+$/)) return 'email-addr';
    }
    if (obj.indicator) {
      // Handle indicator-specific patterns
      if (TYPE_PATTERNS['ipv4-addr'].test(obj.indicator)) return 'ipv4-addr';
      if (TYPE_PATTERNS['ipv6-addr'].test(obj.indicator)) return 'ipv6-addr';
      if (TYPE_PATTERNS['url'].test(obj.indicator)) return 'url';
      if (TYPE_PATTERNS['email-address'].test(obj.indicator)) return 'email-addr';
      if (TYPE_PATTERNS['mac-address'].test(obj.indicator)) return 'mac-address';
      if (
        TYPE_PATTERNS.md5.test(obj.indicator) ||
        TYPE_PATTERNS.sha1.test(obj.indicator) ||
        TYPE_PATTERNS.sha256.test(obj.indicator) ||
        TYPE_PATTERNS.sha512.test(obj.indicator)
      ) return 'file';
      if (TYPE_PATTERNS['domain-name'].test(obj.indicator) && !obj.indicator.includes(' ')) return 'domain-name';
      return 'indicator'; // Default for generic indicators
    }
    if (obj.name) {
      if (obj.labels?.includes('malicious') || obj.malwareTypes?.length) return 'malware';
      if (obj.threatActorTypes?.length || obj.roles?.length) return 'threat-actor';
      if (obj.labels?.includes('campaign')) return 'campaign';
      if (obj.labels?.includes('tool')) return 'tool';
    }

    // Fallback to provided type or 'observed-data'
    return obj.type || 'observed-data';
  }

  /**
   * Validates if a type is a valid STIX 2.1 type.
   */
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
   * Builds a detailed description with new enrichment data (hybrid, threatcrowd, misp).
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
          `- **Geolocation:** ${indicator.enrichment.geo.country_name} (Lat: ${indicator.enrichment.geo.lat || 'N/A'}, Lon: ${indicator.enrichment.geo.lon || 'N/A'})`,
        );
      }
      if (indicator.enrichment.whois?.WhoisRecord) {
        const { registrarName, createdDate } = indicator.enrichment.whois.WhoisRecord;
        enrichmentParts.push(`- **Whois:** Registrar: ${registrarName || 'N/A'}, Created: ${createdDate || 'N/A'}`);
      }
      if (indicator.enrichment.virustotal?.data?.attributes?.last_analysis_stats) {
        const stats = indicator.enrichment.virustotal.data.attributes.last_analysis_stats;
        enrichmentParts.push(
          `- **VirusTotal:** ${stats.malicious}/${stats.total ?? stats.malicious + (stats.undetected ?? 0)} malicious scans`,
        );
      }
      if (indicator.enrichment.abuseipdb?.data) {
        enrichmentParts.push(
          `- **AbuseIPDB:** ${indicator.enrichment.abuseipdb.data.totalReports || 0} reports, Score: ${indicator.enrichment.abuseipdb.data.abuseConfidenceScore || 'N/A'}`,
        );
      }
      if (indicator.enrichment.shodan?.hostnames?.length) {
        enrichmentParts.push(
          `- **Shodan:** Hostnames: ${indicator.enrichment.shodan.hostnames.join(', ')}, Ports: ${indicator.enrichment.shodan.ports?.join(', ') || 'N/A'}`,
        );
      }
      if (indicator.enrichment.threatfox?.data?.length) {
        enrichmentParts.push(
          `- **ThreatFox:** ${indicator.enrichment.threatfox.data.length} IOCs, Malware: ${indicator.enrichment.threatfox.data[0]?.malware || 'N/A'}`,
        );
      }
      if (indicator.enrichment.dns?.Answer?.length) {
        enrichmentParts.push(
          `- **DNS:** ${indicator.enrichment.dns.Answer.map((a: any) => `${a.type}: ${a.data}`).join(', ')}`,
        );
      }
      if (indicator.enrichment.ssl?.endpoints?.length) {
        enrichmentParts.push(
          `- **SSL:** Grade: ${indicator.enrichment.ssl.endpoints[0].grade || 'N/A'}, Protocols: ${indicator.enrichment.ssl.endpoints[0].protocols?.map((p: any) => p.name).join(', ') || 'N/A'}`,
        );
      }
      if (indicator.enrichment.asn) {
        enrichmentParts.push(
          `- **ASN:** ${indicator.enrichment.asn.asn || 'N/A'} (${indicator.enrichment.asn.org || 'Unknown'})`,
        );
      }
      if (indicator.enrichment.hybrid?.summary) {
        enrichmentParts.push(
          `- **Hybrid Analysis:** Threat Score: ${indicator.enrichment.hybrid.summary.threat_score || 'N/A'}, Verdict: ${indicator.enrichment.hybrid.summary.verdict || 'N/A'}`,
        );
      }
      if (indicator.enrichment.threatcrowd) {
        enrichmentParts.push(
          `- **ThreatCrowd:** Hashes: ${indicator.enrichment.threatcrowd.hashes?.length || 0}, IPs: ${indicator.enrichment.threatcrowd.ips?.length || 0}`,
        );
      }
      if (indicator.enrichment.misp?.events?.length) {
        enrichmentParts.push(
          `- **MISP:** Events: ${indicator.enrichment.misp.events.length}, Tags: ${indicator.enrichment.misp.events[0]?.Event?.tags?.join(', ') || 'N/A'}`,
        );
      }
      if (enrichmentParts.length) parts.push(`**Enrichment Data:**\n${enrichmentParts.join('\n')}`);
    }

    if (indicator.references?.length) parts.push(`**References:**\n- ${indicator.references.join('\n- ')}`);
    if (indicator.relatedIndicators?.length) parts.push(`**Related Indicators:** ${indicator.relatedIndicators.join(', ')}`);

    return parts.join('\n\n');
  }

  /**
   * Creates a complex STIX pattern with new enrichment data.
   */
  static createStixPattern(indicator: GenericStixObject): STIXPattern {
    const primaryValue = indicator.indicator || indicator.value || indicator.name || Object.values(indicator.hashes || {})[0];
    if (!primaryValue) throw new Error('Cannot create STIX pattern: no primary value available');

    const now = new Date().toISOString();
    const oneYearLater = new Date(new Date().setFullYear(new Date().getFullYear() + 1)).toISOString();
    const escapeValue = (val: string) => val.replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\[/g, '\\[').replace(/\]/g, '\\]');

    const stixType = this.identifyStixType(indicator);
    const patternKey = this.getPatternKey(stixType);
    let pattern = `[${patternKey} = '${escapeValue(primaryValue)}']`;

    // Add enrichment-based conditions
    if (stixType === 'domain-name' && indicator.enrichment?.dns?.Answer?.length) {
      const dnsValues = indicator.enrichment.dns.Answer.map((a: any) => escapeValue(a.data));
      pattern += ` AND [domain-name:resolves_to_refs.value IN (${dnsValues.map(v => `'${v}'`).join(', ')})]`;
    }
    if ((stixType === 'ipv4-addr' || stixType === 'ipv6-addr') && indicator.enrichment?.asn?.asn) {
      pattern += ` AND [autonomous-system:number = '${escapeValue(indicator.enrichment.asn.asn)}']`;
    }
    if (stixType === 'file' && indicator.enrichment?.virustotal?.data?.attributes?.names?.length) {
      const fileNames = indicator.enrichment.virustotal.data.attributes.names.map(escapeValue);
      pattern += ` AND [file:name IN (${fileNames.map(n => `'${n}'`).join(', ')})]`;
    }
    if (stixType === 'file' && indicator.enrichment?.hybrid?.hashes) {
      const hashes = Object.entries(indicator.enrichment.hybrid.hashes)
        .filter(([_, value]) => value)
        .map(([type, value]) => `${type.toUpperCase()} = '${escapeValue(value as string)}'`);
      if (hashes.length) pattern += ` AND [file:hashes.(${hashes.join(' OR ')})]`;
    }
    if (stixType === 'mutex' && indicator.enrichment?.threatcrowd?.hashes?.length) {
      const relatedHashes = indicator.enrichment.threatcrowd.hashes.map(escapeValue);
      pattern += ` AND [file:hashes.'SHA-256' IN (${relatedHashes.map(h => `'${h}'`).join(', ')})]`;
    }
    if (stixType === 'malware' && indicator.enrichment?.misp?.events?.length) {
      const mispTags = indicator.enrichment.misp.events.flatMap(e => e.Event?.tags || []).map(escapeValue);
      if (mispTags.length) pattern += ` AND [malware:labels IN (${mispTags.map(t => `'${t}'`).join(', ')})]`;
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