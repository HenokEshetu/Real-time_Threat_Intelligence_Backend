import { v4 as uuidv4 } from 'uuid';
import { GenericStixObject, StixType } from './feed.types';

export const indicatorMappers: Record<string, (raw: any) => GenericStixObject | null> = {
  hybridAnalysis: (raw) => {
    const hash = raw.sha256 || raw.md5 || raw.external_id;
    const baseObj: GenericStixObject = {
      id: `file--${hash || uuidv4()}`,
      type: 'file',
      spec_version: '2.1',
      created: raw.submission_time || new Date().toISOString(),
      modified: raw.submission_time || new Date().toISOString(),
      labels: raw.verdict
        ? [String(raw.verdict)]
        : raw.threat_level
          ? [String(raw.threat_level)]
          : ['hybrid-analysis'],
      description: raw.file_type || raw.type || 'Unknown data',
      external_references: (raw.sha256 || raw.md5 || raw.external_id)
        ? [
            {
              id: uuidv4(),
              source_name: 'Hybrid Analysis',
              external_id: hash,
              url: `https://www.hybrid-analysis.com/sample/${raw?.hashes?.sha256 || raw.indicator}`,
              description: 'Original Hybrid Analysis indicator',
            },
          ]
        : [],
      hashes: {
        MD5: raw.md5 || '',
        'SHA-1': '',
        'SHA-256': raw.sha256 || '',
        'SHA-512': '',
      },
    };

    if (hash) {
      return {
        ...baseObj,
        hashes: {
          MD5: raw.md5 || '',
          'SHA-1': '',
          'SHA-256': raw.sha256 || '',
          'SHA-512': '',
        },
      };
    } else if (raw.ip && raw.ip.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      return { ...baseObj, type: 'ipv4-addr', value: raw.ip };
    } else if (raw.submit_name && raw.submit_name.match(/^https?:\/\//)) {
      return { ...baseObj, type: 'url', value: raw.submit_name };
    } else if (raw.submit_name && raw.submit_name.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)) {
      return { ...baseObj, type: 'domain-name', value: raw.submit_name };
    } else if (raw.email && raw.email.match(/^[^@]+@[^@]+\.[^@]+$/)) {
      return { ...baseObj, type: 'email-addr', value: raw.email };
    } else if (raw.mac && raw.mac.match(/^[a-f0-9]{2}(:[a-f0-9]{2}){5}$/i)) {
      return { ...baseObj, type: 'mac-address', value: raw.mac };
    } else if (raw.verdict === 'malicious' && raw.threat_name) {
      return {
        ...baseObj,
        type: 'malware',
        name: raw.threat_name,
        malwareTypes: raw.malware_family ? [raw.malware_family] : [],
      };
    }
    return { ...baseObj, type: 'observed-data' };
  },

  alienVaultOTX: (raw) => {
    try {
      const typeMap: Record<string, string> = {
        IPv4: 'ipv4-addr',
        IPv6: 'ipv6-addr',
        domain: 'domain-name',
        hostname: 'domain-name',
        URL: 'url',
        'FileHash-MD5': 'file',
        'FileHash-SHA1': 'file',
        'FileHash-SHA256': 'file',
        CVE: 'indicator',
        YARA: 'indicator',
        email: 'email-addr',
      };
      const stixType = (typeMap[raw.type] || 'observed-data') as StixType;
      const hashTypes: Record<string, string> = {
        'FileHash-MD5': 'MD5',
        'FileHash-SHA1': 'SHA-1',
        'FileHash-SHA256': 'SHA-256',
      };

      // Determine the value field
      const value = raw.indicator || raw.value || raw.ioc || raw.address || raw.domain;
      if (!value && (stixType === 'ipv4-addr' || stixType === 'domain-name' || stixType === 'url')) {
        console.warn(`Missing value for ${stixType} in AlienVault OTX data: ${JSON.stringify(raw)}`);
        return null;
      }
  
      const baseObj: GenericStixObject = {
        id: `${stixType}--${value || uuidv4()}`,
        type: stixType,
        spec_version: '2.1',
        created: raw.created || new Date().toISOString(),
        modified: raw.modified || new Date().toISOString(),
        labels: ['alienvault-otx', ...(raw.pulse_info?.tags || raw.tags || [])],
        description: raw.description || raw.pulse_info?.name || raw.name || 'AlienVault OTX indicator',
        external_references: (raw.pulse_info?.id || raw.pulse_id)
          ? [
              {
                id: uuidv4(),
                source_name: 'AlienVault OTX',
                external_id: value || raw.indicator,
                url: `https://otx.alienvault.com/pulse/${raw.pulse_info?.id || raw.pulse_id}`,
                description: 'OTX pulse indicator',
              },
            ]
          : [],
      };
  
      switch (stixType) {
        case 'ipv4-addr':
        case 'ipv6-addr':
        case 'domain-name':
        case 'url':
          return { ...baseObj, value, indicator: value }; // Set both value and indicator
        case 'file':
          return {
            ...baseObj,
            hashes: {
              [hashTypes[raw.type]]: value,
              MD5: raw.type === 'FileHash-MD5' ? value : '',
              'SHA-1': raw.type === 'FileHash-SHA1' ? value : '',
              'SHA-256': raw.type === 'FileHash-SHA256' ? value : '',
              'SHA-512': '',
            },
          };
        case 'indicator':
          return {
            ...baseObj,
            indicator: value,
            pattern: `[${raw.type.toLowerCase()}='${value}']`,
            pattern_type: 'stix',
          };
          case 'email-addr': 
          return { ...baseObj, value, indicator: value };
        default:
          return {
            ...baseObj,
            object_refs: [`${raw.type.toLowerCase()}--${uuidv4()}`],
            number_observed: 1,
          };
      }
    } catch (e) {
      console.error(`Mapper error: ${(e as Error).message}`, { raw: JSON.stringify(raw) });
      return null;
    }
  },
};