import { v4 as uuidv4 } from 'uuid';
import { GenericStixObject, StixType, TLPMarkingDefinition } from './feed.types';

export const indicatorMappers: Record<string, (raw: any) => GenericStixObject | GenericStixObject[] | null> = {
  hybridAnalysis: (raw: any): GenericStixObject | GenericStixObject[] | null => {
    try {
      // Validate input
      if (!raw || typeof raw !== 'object') {
        console.warn(`Invalid Hybrid Analysis data: ${JSON.stringify(raw, null, 2).substring(0, 500)}`);
        return null;
      }
  
      // Normalize timestamps
      const created = raw.analysis_start_time ? new Date(raw.analysis_start_time).toISOString() : new Date().toISOString();
      const modified = raw.analysis_start_time ? new Date(raw.analysis_start_time).toISOString() : created;
  
      // Extract metadata
      const jobId = raw.job_id || 'unknown';
      const verdict = raw.threat_level_human || 'unknown';
      const threatScore = raw.threat_score || 0;
      const avDetect = raw.av_detect || 0;
      const fileType = raw.type || 'Unknown';
      const submitName = raw.submit_name || '';
      const isUrlAnalysis = raw.url_analysis || false;
      const environment = raw.environment_description || 'Unknown';
      const processes = Array.isArray(raw.processes) ? raw.processes : [];
      const domains = Array.isArray(raw.domains) ? raw.domains : [];
      const hosts = Array.isArray(raw.hosts) ? raw.hosts : [];
      const extractedFiles = Array.isArray(raw.extracted_files) ? raw.extracted_files : [];
      const geolocation = Array.isArray(raw.hosts_geolocation) ? raw.hosts_geolocation : [];
      const reportUrl = raw.report_url ? `https://www.hybrid-analysis.com${raw.report_url}` : null;
      const tags = Array.isArray(raw.tags) ? raw.tags : [];
  
      // Compute confidence score
      const confidence = Math.min(
        100,
        Math.max(
          0,
          (verdict === 'malicious' ? 30 : verdict === 'suspicious' ? 20 : 10) +
            (threatScore > 0 ? Math.min(threatScore, 50) : 0) +
            (avDetect > 0 ? Math.min(avDetect * 5, 20) : 0) +
            (processes.length > 0 ? 10 : 0)
        )
      );
  
      // Description
      const description = [
        `Hybrid Analysis sample: ${fileType}`,
        `Verdict: ${verdict}`,
        `Threat Score: ${threatScore}`,
        `Environment: ${environment}`,
        processes.length > 0 ? `Processes: ${processes.map((p: any) => p.name).join(', ')}` : null,
        tags.length > 0 ? `Tags: ${tags.join(', ')}` : null,
      ]
        .filter(Boolean)
        .join('; ');
  
      // External references
      const externalReferences = [];
      if (raw.sha256 || raw.md5 || jobId) {
        externalReferences.push({
          id: uuidv4(),
          source_name: 'Hybrid Analysis',
          external_id: raw.sha256 || raw.md5 || jobId,
          url: reportUrl || `https://www.hybrid-analysis.com/sample/${raw.sha256 || raw.md5 || jobId}`,
          description: 'Hybrid Analysis sample',
        });
      }
  
      // TLP marking (default to 'white')
      const tlp = raw.tlp || 'white';
      const tlpMarking: TLPMarkingDefinition = {
        id: `marking-definition--${uuidv4()}`,
        type: 'marking-definition',
        spec_version: '2.1',
        created,
        definition_type: 'tlp',
        definition: { tlp: tlp as 'white' | 'green' | 'amber' | 'red' },
      };
  
      // Base STIX object
      const baseObj: GenericStixObject = {
        id: `file--${raw.sha256 || raw.md5 || uuidv4()}`,
        type: 'file',
        spec_version: '2.1',
        created,
        modified,
        labels: [
          'hybrid-analysis',
          `verdict:${verdict.toLowerCase()}`,
          ...(geolocation.map((geo: any) => `geolocation:${geo.country?.toLowerCase() || 'unknown'}`)),
          ...tags.map((tag: string) => `tag:${tag.toLowerCase()}`),
        ],
        description,
        confidence,
        external_references: externalReferences.length > 0 ? externalReferences : undefined,
        sourceConfigId: 'hybrid-analysis-feed',
        object_marking_refs: [tlpMarking.id],
      };
  
      // Collect STIX objects and relationships
      const stixObjects: GenericStixObject[] = [];
      const relationships: GenericStixObject[] = [];
      const primaryFileId = raw.sha256 ? `file--${raw.sha256}` : null;
  
      // Handle primary file (hashes)
      if (raw.sha256 || raw.md5 || raw.sha1) {
        const hashes: Record<'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512', string | undefined> = {
          MD5: typeof raw.md5 === 'string' && /^[0-9a-fA-F]{32}$/.test(raw.md5) ? raw.md5 : undefined,
          'SHA-1': typeof raw.sha1 === 'string' && /^[0-9a-fA-F]{40}$/.test(raw.sha1) ? raw.sha1 : undefined,
          'SHA-256': typeof raw.sha256 === 'string' && /^[0-9a-fA-F]{64}$/.test(raw.sha256) ? raw.sha256 : undefined,
          'SHA-512': undefined,
        };
        if (hashes['MD5'] || hashes['SHA-1'] || hashes['SHA-256']) {
          const fileObj: GenericStixObject = {
            ...baseObj,
            id: `file--${raw.sha256 || raw.md5 || uuidv4()}`,
            type: 'file',
            hashes,
          };
          stixObjects.push(fileObj);
        } else {
          console.warn(`Invalid hash values in Hybrid Analysis data: ${JSON.stringify(raw, null, 2).substring(0, 500)}`);
        }
      }
  
      // Handle URL (submit_name)
      if (isUrlAnalysis && submitName && typeof submitName === 'string' && submitName.match(/^https?:\/\//)) {
        try {
          new URL(submitName);
          const urlObj: GenericStixObject = {
            ...baseObj,
            id: `url--${uuidv4()}`,
            type: 'url',
            value: submitName,
            indicator: submitName,
          };
          stixObjects.push(urlObj);
          if (primaryFileId) {
            relationships.push({
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              source_ref: primaryFileId,
              target_ref: urlObj.id,
              relationship_type: 'downloaded-from',
              created,
              modified,
            });
          }
        } catch {
          console.warn(`Invalid URL value: ${submitName}`);
        }
      }
  
      // Handle domains
      domains.forEach((domain: string) => {
        if (typeof domain === 'string' && domain.match(/^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/)) {
          const domainObj: GenericStixObject = {
            ...baseObj,
            id: `domain-name--${domain}`,
            type: 'domain-name',
            value: domain,
            indicator: domain,
          };
          stixObjects.push(domainObj);
        } else {
          console.warn(`Invalid domain value: ${domain}`);
        }
      });
  
      // Handle IPs (hosts and et_alerts.destination_ip)
      const uniqueIps = new Set<string>([
        ...hosts,
        ...(Array.isArray(raw.et_alerts) ? raw.et_alerts.map((alert: any) => alert.destination_ip).filter(Boolean) : []),
      ]);
      uniqueIps.forEach((ip: string) => {
        if (typeof ip === 'string' && ip.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) {
          const ipObj: GenericStixObject = {
            ...baseObj,
            id: `ipv4-addr--${ip}`,
            type: 'ipv4-addr',
            value: ip,
            indicator: ip,
          };
          stixObjects.push(ipObj);
          domains.forEach((domain: string) => {
            if (typeof domain === 'string' && domain.match(/^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.[a-zA-Z]{2,}$/)) {
              relationships.push({
                id: `relationship--${uuidv4()}`,
                type: 'relationship',
                spec_version: '2.1',
                source_ref: `domain-name--${domain}`,
                target_ref: ipObj.id,
                relationship_type: 'resolves-to',
                created,
                modified,
              });
            }
          });
          if (primaryFileId) {
            relationships.push({
              id: `relationship--${uuidv4()}`,
              type: 'relationship',
              spec_version: '2.1',
              source_ref: ipObj.id,
              target_ref: primaryFileId,
              relationship_type: 'communicates-with',
              created,
              modified,
            });
          }
        } else {
          console.warn(`Invalid IP value: ${ip}`);
        }
      });
  
      // Handle extracted files
      extractedFiles.forEach((file: any) => {
        if (file.sha256 || file.md5 || file.sha1) {
          const extractedHashes: Record<'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512', string | undefined> = {
            MD5: typeof file.md5 === 'string' && /^[0-9a-fA-F]{32}$/.test(file.md5) ? file.md5 : undefined,
            'SHA-1': typeof file.sha1 === 'string' && /^[0-9a-fA-F]{40}$/.test(file.sha1) ? file.sha1 : undefined,
            'SHA-256': typeof file.sha256 === 'string' && /^[0-9a-fA-F]{64}$/.test(file.sha256) ? file.sha256 : undefined,
            'SHA-512': undefined,
          };
          if (extractedHashes['MD5'] || extractedHashes['SHA-1'] || extractedHashes['SHA-256']) {
            const extractedFileObj: GenericStixObject = {
              ...baseObj,
              id: `file--${file.sha256 || file.md5 || uuidv4()}`,
              type: 'file',
              hashes: extractedHashes,
              description: file.description || `Extracted file: ${file.name || 'Unknown'}`,
              labels: [...baseObj.labels, `type:${file.type_tags?.join(',') || 'unknown'}`],
            };
            stixObjects.push(extractedFileObj);
            if (primaryFileId) {
              relationships.push({
                id: `relationship--${uuidv4()}`,
                type: 'relationship',
                spec_version: '2.1',
                source_ref: extractedFileObj.id,
                target_ref: primaryFileId,
                relationship_type: 'derived-from',
                created,
                modified,
              });
            }
          } else {
            console.warn(`Invalid hash values in extracted file: ${JSON.stringify(file, null, 2).substring(0, 500)}`);
          }
        }
      });
  
      // Handle processes
      processes.forEach((process: any) => {
        if (process.sha256) {
          const processFileObj: GenericStixObject = {
            ...baseObj,
            id: `file--${process.sha256}`,
            type: 'file',
            hashes: {
              MD5: undefined,
              'SHA-1': undefined,
              'SHA-256': typeof process.sha256 === 'string' && /^[0-9a-fA-F]{64}$/.test(process.sha256) ? process.sha256 : undefined,
              'SHA-512': undefined,
            },
            description: `Process: ${process.name || 'Unknown'}; Path: ${process.normalized_path || 'Unknown'}`,
            labels: [...baseObj.labels, 'process'],
          };
          if (processFileObj.hashes['SHA-256']) {
            stixObjects.push(processFileObj);
            if (primaryFileId) {
              relationships.push({
                id: `relationship--${uuidv4()}`,
                type: 'relationship',
                spec_version: '2.1',
                source_ref: processFileObj.id,
                target_ref: primaryFileId,
                relationship_type: 'executed-by',
                created,
                modified,
              });
            }
          } else {
            console.warn(`Invalid hash in process: ${JSON.stringify(process, null, 2).substring(0, 500)}`);
          }
        }
      });
  
      // Fallback to observed-data
      if (stixObjects.length === 0) {
        const observedObj: GenericStixObject = {
          ...baseObj,
          id: `observed-data--${uuidv4()}`,
          type: 'observed-data',
          number_observed: 1,
          first_observed: created,
          last_observed: modified,
          object_refs: [baseObj.id],
        };
        stixObjects.push(observedObj);
      }
  
      // Add TLP marking and relationships
      stixObjects.push(tlpMarking as any);
      stixObjects.push(...relationships);
  
      return stixObjects.length > 0 ? stixObjects : null;
    } catch (e) {
      console.error(`Mapper error for Hybrid Analysis: ${(e as Error).message}`, {
        raw: JSON.stringify(raw, null, 2).substring(0, 500),
      });
      return null;
    }
  },

 alienVaultOTX: (raw: any): GenericStixObject | GenericStixObject[] | null => {
  try {
    // Validate pulse
    if (!raw || typeof raw !== 'object' || !raw.indicators || !Array.isArray(raw.indicators)) {
      console.warn(`Invalid AlienVault OTX pulse data: ${JSON.stringify(raw, null, 2).substring(0, 500)}`);
      return null;
    }

    // Pulse metadata
    const pulseId = raw.id || raw.pulse_id;
    const pulseName = raw.name || 'AlienVault OTX Pulse';
    const pulseDescription = raw.description || pulseName;
    const tags = raw.tags || [];
    const created = raw.created ? new Date(raw.created).toISOString() : new Date().toISOString();
    const modified = raw.modified ? new Date(raw.modified).toISOString() : created;
    const adversary = raw.adversary || '';
    const industries = raw.industries || [];
    const attackIds = raw.attack_ids || [];
    const tlp = raw.tlp || 'white';

    // Compute confidence score
    const confidence = Math.min(
      100,
      Math.max(
        0,
        (tags.includes('apt34') ? 20 : 0) +
          (tags.includes('infrastructure') ? 15 : 0) +
          (raw.public ? 10 : 0) +
          (industries.length > 0 ? 10 : 0) +
          (attackIds.length > 0 ? 10 : 0)
      )
    );

    // External references
    const pulseReferences = pulseId
      ? [
          {
            id: uuidv4(),
            source_name: 'AlienVault OTX',
            external_id: pulseId,
            url: `https://otx.alienvault.com/pulse/${pulseId}`,
            description: 'OTX pulse',
          },
        ]
      : [];
    if (raw.references && Array.isArray(raw.references)) {
      raw.references.forEach((ref: string, index: number) => {
        if (ref && typeof ref === 'string') {
          pulseReferences.push({
            id: uuidv4(),
            source_name: 'AlienVault OTX Reference',
            external_id: `ref-${index}`,
            url: ref,
            description: 'Reference from OTX pulse',
          });
        }
      });
    }

    // TLP marking
    const tlpMarking: TLPMarkingDefinition = {
      id: `marking-definition--${uuidv4()}`,
      type: 'marking-definition',
      spec_version: '2.1',
      created,
      definition_type: 'tlp',
      definition: { tlp: tlp as 'white' | 'green' | 'amber' | 'red' },
    };

    // Map indicators to STIX objects
    const stixObjects: GenericStixObject[] = [];
    const relationships: GenericStixObject[] = [];

    raw.indicators.forEach((indicator: any) => {
      if (!indicator.type || !indicator.indicator) {
        console.warn(`Missing type or indicator in OTX indicator: ${JSON.stringify(indicator, null, 2).substring(0, 500)}`);
        return;
      }

      const typeMap: Record<string, StixType> = {
        'IPv4': 'ipv4-addr',
        'IPv6': 'ipv6-addr',
        'domain': 'domain-name',
        'hostname': 'domain-name',
        'URL': 'url',
        'FileHash-MD5': 'file',
        'FileHash-SHA1': 'file',
        'FileHash-SHA256': 'file',
        'CVE': 'vulnerability',
        'YARA': 'indicator',
        'email': 'email-addr',
      };

      const hashTypes: Record<string, string> = {
        'FileHash-MD5': 'MD5',
        'FileHash-SHA1': 'SHA-1',
        'FileHash-SHA256': 'SHA-256',
      };

      const stixType = typeMap[indicator.type] || 'observed-data';
      const value = indicator.indicator;
      const isActive = indicator.is_active === 1;
      const indicatorDescription = indicator.description || pulseDescription;

      // Skip inactive indicators
      if (!isActive) {
        console.warn(`Skipping inactive OTX indicator: ${value}`);
        return;
      }

      // Base STIX object
      const baseObj: GenericStixObject = {
        id: `${stixType}--${value || uuidv4()}`,
        type: stixType,
        spec_version: '2.1',
        created: indicator.created ? new Date(indicator.created).toISOString() : created,
        modified,
        labels: [
          'alienvault-otx',
          'osint',
          ...tags.map((tag: string) => tag.toLowerCase()),
          ...(adversary ? [`adversary:${adversary.toLowerCase()}`] : []),
          ...(industries.map((ind: string) => `industry:${ind.toLowerCase()}`)),
        ],
        description: indicatorDescription,
        confidence,
        external_references: pulseReferences.length > 0 ? pulseReferences : undefined,
        sourceConfigId: 'alienvault-otx-feed',
        object_marking_refs: [tlpMarking.id],
      };

      // Handle specific STIX types
      let stixObj: GenericStixObject | null = null;
      switch (stixType) {
        case 'ipv4-addr':
        case 'ipv6-addr':
          if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(value)) {
            console.warn(`Invalid ${stixType} value: ${value}`);
            return;
          }
          stixObj = { ...baseObj, value, indicator: value };
          break;

        case 'domain-name':
          if (!/^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/.test(value)) {
            console.warn(`Invalid domain-name value: ${value}`);
            return;
          }
          stixObj = { ...baseObj, value, indicator: value };
          // If hostname, link to parent domain
          if (indicator.type === 'hostname') {
            const parentDomain = value.split('.').slice(-2).join('.');
            if (raw.indicators.some((ind: any) => ind.type === 'domain' && ind.indicator === parentDomain)) {
              const parentObjId = `domain-name--${parentDomain}`;
              relationships.push({
                id: `relationship--${uuidv4()}`,
                type: 'relationship',
                spec_version: '2.1',
                source_ref: baseObj.id,
                target_ref: parentObjId,
                relationship_type: 'related-to',
                created,
                modified,
              });
            }
          }
          break;

        case 'url':
          try {
            new URL(value);
          } catch {
            console.warn(`Invalid url value: ${value}`);
            return;
          }
          stixObj = { ...baseObj, value, indicator: value };
          break;

        case 'email-addr':
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
            console.warn(`Invalid email-addr value: ${value}`);
            return;
          }
          stixObj = { ...baseObj, value, indicator: value };
          break;

        case 'file':
          const hashType = hashTypes[indicator.type];
          if (!hashType || !value.match(/^[0-9a-fA-F]+$/)) {
            console.warn(`Invalid hash for file: ${value}`);
            return;
          }
          stixObj = {
            ...baseObj,
            hashes: {
              [hashType]: value,
              MD5: indicator.type === 'FileHash-MD5' ? value : undefined,
              'SHA-1': indicator.type === 'FileHash-SHA1' ? value : undefined,
              'SHA-256': indicator.type === 'FileHash-SHA256' ? value : undefined,
              'SHA-512': undefined,
            } as Record<'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512', string>,
          };
          break;

        case 'vulnerability':
          if (!value.startsWith('CVE-')) {
            console.warn(`Invalid CVE value: ${value}`);
            return;
          }
          stixObj = {
            ...baseObj,
            name: value,
            description: indicatorDescription || `Vulnerability ${value} from AlienVault OTX`,
          };
          break;

        case 'indicator':
          stixObj = {
            ...baseObj,
            indicator: value,
            pattern: `[${indicator.type.toLowerCase()}:value = '${value}']`,
            pattern_type: 'stix',
          };
          break;

        case 'observed-data':
          stixObj = {
            ...baseObj,
            object_refs: [`${indicator.type.toLowerCase()}--${uuidv4()}`],
            number_observed: 1,
            first_observed: created,
            last_observed: modified,
          };
          break;

        default:
          console.warn(`Unsupported STIX type: ${stixType} for OTX indicator: ${JSON.stringify(indicator, null, 2).substring(0, 500)}`);
          return;
      }

      if (stixObj) {
        stixObjects.push(stixObj);
      }
    });

    // Add TLP marking and relationships
    if (stixObjects.length > 0) {
      stixObjects.push(tlpMarking as any); // Cast to GenericStixObject
      stixObjects.push(...relationships);
      return stixObjects;
    }

    console.warn(`No valid STIX objects generated for OTX pulse: ${pulseId || 'unknown'}`);
    return null;
  } catch (e) {
    console.error(`Mapper error for AlienVault OTX: ${(e as Error).message}`, {
      raw: JSON.stringify(raw, null, 2).substring(0, 500),
    });
    return null;
  }
},

 misp: (raw: any): GenericStixObject | null => {
   try {
     // Validate MISP event or attribute structure
     if (!raw || (!raw.Event && !raw.Attribute && !raw.response?.Attribute)) {
       console.warn(`Invalid MISP data: missing Event or Attribute - ${JSON.stringify(raw)}`);
       return null;
     }

     // Handle MISP event or attribute
     const isEvent = !!raw.Event;
     const event = isEvent ? raw.Event : raw;
     const attributes = (isEvent ? event.Attribute : raw.response?.Attribute) || [];

     // Base properties for all STIX objects
     const baseObj: GenericStixObject = {
       id: `indicator--${event.uuid || uuidv4()}`,
       type: 'indicator',
       spec_version: '2.1',
       created: event.date ? new Date(event.date).toISOString() : new Date().toISOString(),
       modified: event.timestamp
         ? new Date(parseInt(event.timestamp) * 1000).toISOString()
         : new Date().toISOString(),
       labels: [
         'misp',
         ...(event.Tag?.map((tag: any) => tag.name) || []),
         ...(event.info ? [event.info.substring(0, 50)] : []),
       ],
       description: event.info || 'MISP event or attribute',
       external_references: [
         {
           id: uuidv4(),
           source_name: 'MISP',
           external_id: event.uuid || raw.uuid,
           url: event.uuid ? `http://localhost/events/${event.uuid}` : undefined,
           description: `MISP ${isEvent ? 'event' : 'attribute'}`,
         },
       ],
     };

     // Map MISP attribute types to STIX 2.1 types
     const mispToStixType: Record<string, StixType> = {
       'md5': 'file',
       'sha1': 'file',
       'sha256': 'file',
       'sha512': 'file',
       'sha224': 'file',
       'sha384': 'file',
       'sha512/224': 'file',
       'sha512/256': 'file',
       'sha3-224': 'file',
       'sha3-256': 'file',
       'sha3-384': 'file',
       'sha3-512': 'file',
       'ssdeep': 'file',
       'imphash': 'file',
       'telfhash': 'file',
       'impfuzzy': 'file',
       'authentihash': 'file',
       'vhash': 'file',
       'pehash': 'file',
       'tlsh': 'file',
       'cdhash': 'file',
       'filename': 'file',
       'filename|md5': 'file',
       'filename|sha1': 'file',
       'filename|sha256': 'file',
       'filename|sha512': 'file',
       'filename|sha224': 'file',
       'filename|sha384': 'file',
       'filename|sha512/224': 'file',
       'filename|sha512/256': 'file',
       'filename|sha3-224': 'file',
       'filename|sha3-256': 'file',
       'filename|sha3-384': 'file',
       'filename|sha3-512': 'file',
       'filename|ssdeep': 'file',
       'filename|imphash': 'file',
       'filename|impfuzzy': 'file',
       'filename|authentihash': 'file',
       'filename|vhash': 'file',
       'filename|pehash': 'file',
       'filename|tlsh': 'file',
       'pdb': 'file',
       'malware-sample': 'file',
       'ip-src': 'ipv4-addr',
       'ip-dst': 'ipv4-addr',
       'ip-src|port': 'network-traffic',
       'ip-dst|port': 'network-traffic',
       'hostname': 'domain-name',
       'domain': 'domain-name',
       'domain|ip': 'domain-name',
       'url': 'url',
       'uri': 'url',
       'email': 'email-addr',
       'email-src': 'email-addr',
       'email-dst': 'email-addr',
       'email-subject': 'email-message',
       'email-attachment': 'file',
       'email-body': 'email-message',
       'email-dst-display-name': 'email-addr',
       'email-src-display-name': 'email-addr',
       'email-header': 'email-message',
       'email-reply-to': 'email-addr',
       'email-x-mailer': 'email-message',
       'email-mime-boundary': 'email-message',
       'email-thread-index': 'email-message',
       'email-message-id': 'email-message',
       'user-agent': 'software',
       'http-method': 'network-traffic',
       'ja3-fingerprint-md5': 'network-traffic',
       'jarm-fingerprint': 'network-traffic',
       'favicon-mmh3': 'file',
       'hassh-md5': 'network-traffic',
       'hasshserver-md5': 'network-traffic',
       'regkey': 'windows-registry-key',
       'regkey|value': 'windows-registry-key',
       'AS': 'autonomous-system',
       'snort': 'indicator',
       'bro': 'indicator',
       'zeek': 'indicator',
       'community-id': 'network-traffic',
       'dom-hash': 'indicator',
       'pattern-in-file': 'indicator',
       'pattern-in-traffic': 'indicator',
       'pattern-in-memory': 'indicator',
       'filename-pattern': 'indicator',
       'yara': 'indicator',
       'stix2-pattern': 'indicator',
       'sigma': 'indicator',
       'vulnerability': 'vulnerability',
       'cpe': 'software',
       'weakness': 'vulnerability',
       'attachment': 'artifact',
       'link': 'url',
       'comment': 'note',
       'text': 'note',
       'hex': 'artifact',
       'other': 'observed-data',
       'named pipe': 'file',
       'mutex': 'mutex',
       'process-state': 'process',
       'target-user': 'user-account',
       'target-email': 'email-addr',
       'target-machine': 'infrastructure',
       'target-org': 'identity',
       'target-location': 'location',
       'target-external': 'identity',
       'btc': 'user-account',
       'dash': 'user-account',
       'xmr': 'user-account',
       'iban': 'user-account',
       'bic': 'user-account',
       'bank-account-nr': 'user-account',
       'aba-rtn': 'user-account',
       'bin': 'user-account',
       'cc-number': 'user-account',
       'prtn': 'user-account',
       'phone-number': 'user-account',
       'threat-actor': 'threat-actor',
       'campaign-name': 'campaign',
       'campaign-id': 'campaign',
       'malware-type': 'malware',
       'x509-fingerprint-sha1': 'x509-certificate',
       'x509-fingerprint-md5': 'x509-certificate',
       'x509-fingerprint-sha256': 'x509-certificate',
       'dns-soa-email': 'email-addr',
       'size-in-bytes': 'observed-data',
       'counter': 'observed-data',
       'integer': 'observed-data',
       'datetime': 'observed-data',
       'port': 'network-traffic',
       'mac-address': 'mac-address',
       'mac-eui-64': 'mac-address',
       'github-username': 'user-account',
       'github-repository': 'url',
       'github-organisation': 'identity',
       'jabber-id': 'user-account',
       'twitter-id': 'user-account',
       'dkim': 'artifact',
       'dkim-signature': 'artifact',
       'first-name': 'identity',
       'middle-name': 'identity',
       'last-name': 'identity',
       'full-name': 'identity',
       'date-of-birth': 'identity',
       'place-of-birth': 'location',
       'gender': 'identity',
       'passport-number': 'identity',
       'passport-country': 'location',
       'passport-expiration': 'identity',
       'redress-number': 'identity',
       'nationality': 'identity',
       'visa-number': 'identity',
       'issue-date-of-the-visa': 'identity',
       'primary-residence': 'location',
       'country-of-residence': 'location',
       'special-service-request': 'identity',
       'frequent-flyer-number': 'identity',
       'travel-details': 'identity',
       'payment-details': 'identity',
       'place-port-of-original-embarkation': 'location',
       'place-port-of-clearance': 'location',
       'place-port-of-onward-foreign-destination': 'location',
       'passenger-name-record-locator-number': 'identity',
       'mobile-application-id': 'software',
       'azure-application-id': 'software',
       'chrome-extension-id': 'software',
       'cortex': 'indicator',
       'boolean': 'observed-data',
       'anonymised': 'observed-data',
     };
      // Handle MISP Galaxy clusters (e.g., MITRE ATT&CK, malware families)
   const galaxyClusters = event.GalaxyCluster?.map((cluster: any) => ({
     type: cluster.type.includes('mitre-attack-pattern') ? 'attack-pattern' : 'malware',
     name: cluster.value,
     description: cluster.description,
     external_references: [
       {
         id: uuidv4(),
         source_name: 'MISP Galaxy',
         external_id: cluster.uuid,
         description: `MISP Galaxy: ${cluster.type}`,
       },
     ],
   })) || [];

   // If processing an event without attributes, map to a STIX report
   if (isEvent && attributes.length === 0) {
     return {
       ...baseObj,
       type: 'report',
       name: event.info || 'MISP Event',
       published: event.publish_timestamp
         ? new Date(parseInt(event.publish_timestamp) * 1000).toISOString()
         : baseObj.created,
       object_refs: galaxyClusters.map((gc: any) => `${gc.type}--${uuidv4()}`),
       labels: [...baseObj.labels, 'event'],
     };
   }

   // Process attributes
   if (attributes.length > 0) {
     const attribute = attributes[0]; // Process first attribute for consistency
     const stixType = mispToStixType[attribute.type] || 'observed-data';
     const value = attribute.value;
     const category = attribute.category || raw.sane_defaults?.[attribute.type]?.default_category || 'Other';
     const toIds = attribute.to_ids ?? raw.sane_defaults?.[attribute.type]?.to_ids ?? 0;

     if (!value) {
       console.warn(`Missing value for MISP attribute: ${JSON.stringify(attribute)}`);
       return null;
     }

     // Determine if attribute should be an indicator based on to_ids
     const effectiveType = toIds && stixType !== 'observed-data' ? 'indicator' : stixType;

     // Handle composite attributes (e.g., filename|md5, domain|ip)
     let compositeValues: string[] | undefined;
     if (attribute.type.includes('|')) {
       compositeValues = value.split('|').map((v: string) => v.trim());
     }

     switch (effectiveType) {
       case 'file':
         // Define hashTypeMap and hashType in this scope
         const hashTypeMap: Record<string, string> = {
           md5: 'MD5',
           sha1: 'SHA-1',
           sha256: 'SHA-256',
           sha512: 'SHA-512',
           'sha224': 'SHA-224',
           'sha384': 'SHA-384',
           'sha512/224': 'SHA-512/224',
           'sha512/256': 'SHA-512/256',
           'sha3-224': 'SHA3-224',
           'sha3-256': 'SHA3-256',
           'sha3-384': 'SHA3-384',
           'sha3-512': 'SHA3-512',
           ssdeep: 'SSDEEP',
           imphash: 'IMPHASH',
           telfhash: 'TELFHASH',
           impfuzzy: 'IMPFUZZY',
           authentihash: 'AUTHENTIHASH',
           vhash: 'VHASH',
           pehash: 'PEHASH',
           tlsh: 'TLSH',
           cdhash: 'CDHASH',
         };
         const hashType = hashTypeMap[attribute.type.split('|')[0]] || 'SHA-256';
         const fileName = compositeValues?.[0] || (attribute.type === 'filename' ? value : undefined);
         const hashes: Record<'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512', string> = {
           MD5: '',
           'SHA-1': '',
           'SHA-256': '',
           'SHA-512': '',
         };
         if (compositeValues) {
           const hashKey = hashTypeMap[attribute.type.split('|')[1]];
           if (hashKey && (hashKey === 'MD5' || hashKey === 'SHA-1' || hashKey === 'SHA-256' || hashKey === 'SHA-512')) {
             hashes[hashKey as keyof typeof hashes] = compositeValues[1];
           }
         } else {
           if (hashType === 'MD5' || hashType === 'SHA-1' || hashType === 'SHA-256' || hashType === 'SHA-512') {
             hashes[hashType as keyof typeof hashes] = value;
           }
         }
         return {
           ...baseObj,
           type: 'file',
           hashes,
           name: fileName,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
         case 'ipv4-addr':
           case 'ipv6-addr':
             const ipValue = compositeValues?.[0] || value;
             if (!ipValue || ipValue === 'undefined') {
               console.warn(`Invalid IP value for MISP attribute: ${JSON.stringify(attribute)}`);
               return null;
             }
             return {
               ...baseObj,
               type: ipValue.includes(':') ? 'ipv6-addr' : 'ipv4-addr',
               value: ipValue,
               indicator: toIds ? ipValue : undefined,
               labels: [...baseObj.labels, category.toLowerCase()],
             };
       case 'domain-name':
         const resolvesToRefs = compositeValues?.[1]
           ? [`${compositeValues[1].includes(':') ? 'ipv6-addr' : 'ipv4-addr'}--${uuidv4()}`]
           : undefined;
         return {
           ...baseObj,
           type: 'domain-name',
           value: compositeValues?.[0] || value,
           resolves_to_refs: resolvesToRefs,
           indicator: toIds ? value : undefined,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'url':
         return {
           ...baseObj,
           type: 'url',
           value,
           indicator: toIds ? value : undefined,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'email-addr':
         return {
           ...baseObj,
           type: 'email-addr',
           value,
           indicator: toIds ? value : undefined,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'email-message':
         return {
           ...baseObj,
           type: 'email-message',
           [attribute.type.includes('subject') ? 'subject' : 'body']: value,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'mac-address':
         return {
           ...baseObj,
           type: 'mac-address',
           value,
           indicator: toIds ? value : undefined,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'mutex':
         return {
           ...baseObj,
           type: 'mutex',
           name: value,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'autonomous-system':
         return {
           ...baseObj,
           type: 'autonomous-system',
           number: parseInt(value.replace('AS', ''), 10) || 0,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'vulnerability':
         return {
           ...baseObj,
           type: 'vulnerability',
           name: value,
           description: attribute.comment || `Vulnerability ${value}`,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'malware':
         return {
           ...baseObj,
           type: 'malware',
           name: value,
           malware_types: category === 'Payload delivery' ? ['trojan'] : ['unknown'],
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'threat-actor':
         return {
           ...baseObj,
           type: 'threat-actor',
           name: value,
           threat_actor_types: ['unknown'],
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'campaign':
         return {
           ...baseObj,
           type: 'campaign',
           name: value,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'indicator':
         return {
           ...baseObj,
           type: 'indicator',
           indicator: value,
           pattern: `[${attribute.type}='${value}']`,
           pattern_type: 'stix',
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'network-traffic':
         const [ip, port] = compositeValues || [value, undefined];
         return {
           ...baseObj,
           type: 'network-traffic',
           dst_ref: ip ? `${ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr'}--${uuidv4()}` : undefined,
           dst_port: port ? parseInt(port, 10) : undefined,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'software':
         return {
           ...baseObj,
           type: 'software',
           name: value,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'windows-registry-key':
         const [key, regValue] = compositeValues || [value, undefined];
         return {
           ...baseObj,
           type: 'windows-registry-key',
           key,
           values: regValue ? [{ name: regValue }] : undefined,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'x509-certificate':
         // Always provide all required hash keys
         const x509Hashes: Record<'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512', string> = {
           MD5: '',
           'SHA-1': '',
           'SHA-256': '',
           'SHA-512': '',
         };
         const hashAlg = attribute.type.split('-')[2]?.toUpperCase();
         if (hashAlg && x509Hashes.hasOwnProperty(hashAlg)) {
           x509Hashes[hashAlg as keyof typeof x509Hashes] = value;
         }
         return {
           ...baseObj,
           type: 'x509-certificate',
           hashes: x509Hashes,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'user-account':
         return {
           ...baseObj,
           type: 'user-account',
           account_login: value,
           account_type: category === 'Financial fraud' ? 'financial' : 'unknown',
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'identity':
         return {
           ...baseObj,
           type: 'identity',
           name: value,
           identity_class: category === 'Person' ? 'individual' : 'organization',
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'location':
         return {
           ...baseObj,
           type: 'location',
           name: value,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'infrastructure':
         return {
           ...baseObj,
           type: 'infrastructure',
           name: value,
           infrastructure_types: ['unknown'],
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'artifact':
         return {
           ...baseObj,
           type: 'artifact',
           payload_bin: value,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'note':
         return {
           ...baseObj,
           type: 'note',
           content: value,
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'process':
         return {
           ...baseObj,
           type: 'process',
           arguments: [value],
           labels: [...baseObj.labels, category.toLowerCase()],
         };
       case 'observed-data':
       default:
         return {
           ...baseObj,
           type: 'observed-data',
           first_observed: baseObj.created,
           last_observed: baseObj.modified,
           number: 1, // Use 'number' instead of 'number_observed'
           object_refs: [`${stixType}--${uuidv4()}`],
           labels: [...baseObj.labels, category.toLowerCase()],
         };
     }
   }

   // Handle Galaxy clusters as standalone objects
   if (galaxyClusters.length > 0) {
     const cluster = galaxyClusters[0];
     return {
       ...baseObj,
       type: cluster.type as StixType,
       name: cluster.name,
       description: cluster.description,
       external_references: [...baseObj.external_references, ...cluster.external_references],
       labels: [...baseObj.labels, 'galaxy-cluster'],
     };
   }

   // Default to indicator if no specific mapping applies
   return {
     ...baseObj,
     type: 'indicator',
     indicator: event.info || attributes[0]?.value,
     pattern: `[misp-event='${event.uuid}']`,
     pattern_type: 'stix',
     labels: [...baseObj.labels, 'event'],
   };
 } catch (e) {
   console.error(`MISP mapper error: ${(e as Error).message}`, { raw: JSON.stringify(raw) });
   return null;
 }
 }
};