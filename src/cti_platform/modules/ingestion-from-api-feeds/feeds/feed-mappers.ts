import { v5 as uuidv5 } from 'uuid';
import moment from 'moment';
import { TLPMarkingDefinition, StixType, GenericStixObject } from './feed.types';

// Constants
const STIX_VERSION = '2.1';
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
const MISP_BASE_URL = process.env.MISP_BASE_URL || 'http://localhost';

// Utility Functions
const generateStixId = (type: string, value: string): string => {
  return `${type}--${uuidv5(value, NAMESPACE)}`;
};

const createTLPMarking = (tlp: 'white' | 'green' | 'amber' | 'red', timestamp: number): TLPMarkingDefinition => ({
  id: generateStixId('marking-definition', `tlp_${tlp}_${timestamp}`),
  type: 'marking-definition',
  spec_version: STIX_VERSION,
  created: moment(timestamp * 1000).toISOString(),
  definition_type: 'tlp',
  definition: { tlp },
});

const createRelationship = (
  sourceId: string,
  targetId: string,
  relationshipType: string,
  timestamp: number,
  description?: string,
  startTime?: string,
  stopTime?: string,
): GenericStixObject => {
  const validRelationships = new Map<string, Set<string>>([
    ['attack-pattern', new Set(['delivers', 'targets', 'uses'])],
    ['campaign', new Set(['attributed-to', 'compromises', 'originates-from', 'targets', 'uses'])],
    ['course-of-action', new Set(['investigates', 'mitigates'])],
    ['identity', new Set(['located-at'])],
    ['indicator', new Set(['indicates', 'based-on'])],
    ['infrastructure', new Set(['communicates-with', 'consists-of', 'controls', 'delivers', 'has', 'hosts', 'located-at', 'uses'])],
    ['intrusion-set', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'originates-from', 'targets', 'uses'])],
    ['malware', new Set(['authored-by', 'beacons-to', 'exfiltrate-to', 'communicates-with', 'controls', 'downloads', 'drops', 'exploits', 'originates-from', 'targets', 'uses', 'variant-of'])],
    ['malware-analysis', new Set(['characterizes', 'analysis-of', 'static-analysis-of', 'dynamic-analysis-of'])],
    ['threat-actor', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'impersonates', 'located-at', 'targets', 'uses'])],
    ['tool', new Set(['delivers', 'drops', 'has', 'targets'])],
  ]);
  
  const validTargets = new Map<string, Set<string>>([
    ['delivers', new Set(['malware'])],
    ['targets', new Set(['identity', 'location', 'vulnerability', 'infrastructure'])],
    ['uses', new Set(['attack-pattern', 'infrastructure', 'malware', 'tool'])],
    ['attributed-to', new Set(['intrusion-set', 'threat-actor', 'identity'])],
    ['compromises', new Set(['infrastructure'])],
    ['originates-from', new Set(['location'])],
    ['investigates', new Set(['indicator'])],
    ['mitigates', new Set(['attack-pattern', 'indicator', 'malware', 'tool', 'vulnerability'])],
    ['located-at', new Set(['location'])],
    ['indicates', new Set(['attack-pattern', 'campaign', 'infrastructure', 'intrusion-set', 'malware', 'threat-actor', 'tool'])],
    ['based-on', new Set([
      'observed-data',
      'ipv4-addr',
      'ipv6-addr',
      'domain-name',
      'url',
      'email-addr',
      'file',
      'mutex',
      'windows-registry-key',
      'x509-certificate',
      'autonomous-system',
      'network-traffic',
      'software',
      'user-account',
      'mac-addr',
      'process',
      'directory',
      'artifact'
    ])],
    ['communicates-with', new Set(['infrastructure'])],
    ['consists-of', new Set(['infrastructure'])],
    ['controls', new Set(['infrastructure', 'malware'])],
    ['has', new Set(['vulnerability'])],
    ['hosts', new Set(['infrastructure', 'malware'])],
    ['authored-by', new Set(['threat-actor'])],
    ['beacons-to', new Set(['infrastructure'])],
    ['exfiltrate-to', new Set(['infrastructure'])],
    ['downloads', new Set(['malware', 'tool'])],
    ['drops', new Set(['malware', 'tool'])],
    ['exploits', new Set(['vulnerability'])],
    ['variant-of', new Set(['malware'])],
    ['characterizes', new Set(['malware'])],
    ['analysis-of', new Set(['malware'])],
    ['static-analysis-of', new Set(['malware'])],
    ['dynamic-analysis-of', new Set(['malware'])],
    ['owns', new Set(['infrastructure'])],
    ['impersonates', new Set(['identity'])],
  ]);
  // Extract source and target types from IDs
  const sourceType = sourceId.split('--')[0];
  const targetType = targetId.split('--')[0];

  // Validate relationship type for source
  if (!validRelationships.get(sourceType)?.has(relationshipType)) {
    console.warn(`Invalid relationship type ${relationshipType} for source ${sourceType}: ${sourceId}`);
    throw new Error(`Invalid relationship type: ${relationshipType} not allowed for ${sourceType}`);
  }

  // Validate target type for relationship
  if (!validTargets.get(relationshipType)?.has(targetType)) {
    console.warn(`Invalid target ${targetType} for relationship ${relationshipType} from ${sourceType}: ${sourceId} -> ${targetId}`);
    throw new Error(`Invalid relationship target: ${relationshipType} cannot target ${targetType}`);
  }

  // Create the relationship object
  const relationship: GenericStixObject = {
    id: generateStixId('relationship', `${sourceId}_${relationshipType}_${targetId}`),
    type: 'relationship',
    spec_version: STIX_VERSION,
    relationship_type: relationshipType,
    source_ref: sourceId,
    target_ref: targetId,
    description: description || `Relationship of type ${relationshipType} from MISP data`,
    start_time: startTime,
    stop_time: stopTime,
    created: moment(timestamp * 1000).toISOString(),
    modified: moment(timestamp * 1000).toISOString(),
    object_marking_refs: [createTLPMarking('white', timestamp).id],
  };

  console.log(`Created relationship: ${sourceType} (${sourceId}) ${relationshipType} ${targetType} (${targetId})`);
  return relationship;
};

const createSighting = (
  sightingOf: string,
  whereSighted: string[],
  timestamp: number,
  count?: number,
  summary?: string,
  observedDataRefs?: string[],
  detected: boolean = false,
): GenericStixObject => ({
  id: generateStixId('sighting', `${sightingOf}_sighted_${whereSighted.join('_')}`),
  type: 'sighting',
  spec_version: STIX_VERSION,
  sighting_of_ref: sightingOf,
  where_sighted_refs: whereSighted,
  observed_data_refs: observedDataRefs,
  summary,
  first_seen: moment(timestamp * 1000).toISOString(),
  last_seen: moment(timestamp * 1000).toISOString(),
  count,
  detected,
  created: moment(timestamp * 1000).toISOString(),
  modified: moment(timestamp * 1000).toISOString(),
  object_marking_refs: [createTLPMarking('white', timestamp).id],
});

// Helper function to map MISP analysis to STIX confidence
const mapMispAnalysisToConfidence = (analysis: string): number | undefined => {
  switch (analysis) {
    case 'initial': return 25;
    case 'ongoing': return 50;
    case 'completed': return 75;
    default: return undefined;
  }
};
// Helper Function to Map MISP Relationships to STIX
const mapMispRelationshipToStix = (mispRel: string, sourceType: string, targetType: string): string | null => {
  const mapping: Record<string, string> = {
    'derived-from': 'based-on',
    'delivers': 'delivers',
    'drops': 'drops',
    'attributed-to': 'attributed-to',
    'targets': 'targets',
    'uses': 'uses',
    'indicates': 'indicates',
    'resolves-to': 'resolves-to',
  };
  return mapping[mispRel.toLowerCase()] || null;
};

// Validation Functions
const isValidIp = (ip: string): boolean => {
  if (!ip) return false;
  try {
    if (ip.includes('.')) {
      const parts = ip.split('.');
      if (parts.length !== 4) return false;
      return parts.every(part => {
        const num = parseInt(part, 10);
        return !isNaN(num) && num >= 0 && num <= 255 && part.match(/^(0|[1-9]\d*)$/);
      });
    }
    if (ip.includes(':')) {
      const parts = ip.split(':');
      if (parts.length < 2 || parts.length > 8) return false;
      return parts.every(part => part === '' || /^[0-9a-fA-F]{1,4}$/.test(part));
    }
    return false;
  } catch {
    return false;
  }
};

const isValidDomain = (domain: string): boolean => {
  const domainRegex = /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
};

const isValidEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const isValidUrl = (url: string): boolean => {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
};

const isValidMacAddress = (mac: string): boolean => {
  const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
  return macRegex.test(mac);
};


// MISP to STIX Type Mapping
const MISP_TO_STIX_MAPPING: Record<string, { type: StixType; isSDO?: boolean }> = {
  'md5': { type: 'file' },
  'sha1': { type: 'file' },
  'sha256': { type: 'file' },
  'sha512': { type: 'file' },
  'sha224': { type: 'file' },
  'sha384': { type: 'file' },
  'sha512/224': { type: 'file' },
  'sha512/256': { type: 'file' },
  'sha3-224': { type: 'file' },
  'sha3-256': { type: 'file' },
  'sha3-384': { type: 'file' },
  'sha3-512': { type: 'file' },
  'ssdeep': { type: 'file' },
  'imphash': { type: 'file' },
  'telfhash': { type: 'file' },
  'impfuzzy': { type: 'file' },
  'authentihash': { type: 'file' },
  'vhash': { type: 'file' },
  'pehash': { type: 'file' },
  'tlsh': { type: 'file' },
  'cdhash': { type: 'file' },
  'filename': { type: 'file' },
  'filename|md5': { type: 'file' },
  'filename|sha1': { type: 'file' },
  'filename|sha256': { type: 'file' },
  'filename|sha512': { type: 'file' },
  'filename|sha224': { type: 'file' },
  'filename|sha384': { type: 'file' },
  'filename|sha512/224': { type: 'file' },
  'filename|sha512/256': { type: 'file' },
  'filename|sha3-224': { type: 'file' },
  'filename|sha3-256': { type: 'file' },
  'filename|sha3-384': { type: 'file' },
  'filename|sha3-512': { type: 'file' },
  'filename|ssdeep': { type: 'file' },
  'filename|imphash': { type: 'file' },
  'filename|impfuzzy': { type: 'file' },
  'filename|authentihash': { type: 'file' },
  'filename|vhash': { type: 'file' },
  'filename|pehash': { type: 'file' },
  'filename|tlsh': { type: 'file' },
  'pdb': { type: 'file' },
  'malware-sample': { type: 'file' },
  'ip-src': { type: 'ipv4-addr' },
  'ip-dst': { type: 'ipv4-addr' },
  'ip-src|port': { type: 'network-traffic' },
  'ip-dst|port': { type: 'network-traffic' },
  'hostname': { type: 'domain-name' },
  'domain': { type: 'domain-name' },
  'domain|ip': { type: 'domain-name' },
  'url': { type: 'url' },
  'uri': { type: 'url' },
  'email': { type: 'email-addr' },
  'email-src': { type: 'email-addr' },
  'email-dst': { type: 'email-addr' },
  'email-subject': { type: 'email-message' },
  'email-attachment': { type: 'file' },
  'email-body': { type: 'email-message' },
  'email-dst-display-name': { type: 'email-addr' },
  'email-src-display-name': { type: 'email-addr' },
  'email-header': { type: 'email-message' },
  'email-reply-to': { type: 'email-addr' },
  'email-x-mailer': { type: 'email-message' },
  'email-mime-boundary': { type: 'email-message' },
  'email-thread-index': { type: 'email-message' },
  'email-message-id': { type: 'email-message' },
  'user-agent': { type: 'software' },
  'http-method': { type: 'network-traffic' },
  'ja3-fingerprint-md5': { type: 'network-traffic' },
  'jarm-fingerprint': { type: 'network-traffic' },
  'favicon-mmh3': { type: 'file' },
  'hassh-md5': { type: 'network-traffic' },
  'hasshserver-md5': { type: 'network-traffic' },
  'regkey': { type: 'windows-registry-key' },
  'regkey|value': { type: 'windows-registry-key' },
  'AS': { type: 'autonomous-system' },
  'snort': { type: 'indicator', isSDO: true },
  'bro': { type: 'indicator', isSDO: true },
  'zeek': { type: 'indicator', isSDO: true },
  'community-id': { type: 'network-traffic' },
  'dom-hash': { type: 'indicator', isSDO: true },
  'pattern-in-file': { type: 'indicator', isSDO: true },
  'pattern-in-traffic': { type: 'indicator', isSDO: true },
  'pattern-in-memory': { type: 'indicator', isSDO: true },
  'filename-pattern': { type: 'indicator', isSDO: true },
  'sigma': { type: 'indicator', isSDO: true },
  'vulnerability': { type: 'vulnerability', isSDO: true },
  'cpe': { type: 'software' },
  'weakness': { type: 'vulnerability', isSDO: true },
  'attachment': { type: 'artifact' },
  'link': { type: 'url' },
  'comment': { type: 'note', isSDO: true },
  'text': { type: 'note', isSDO: true },
  'hex': { type: 'artifact' },
  'other': { type: 'observed-data', isSDO: true },
  'named pipe': { type: 'file' },
  'mutex': { type: 'mutex' },
  'process-state': { type: 'process' },
  'target-user': { type: 'user-account' },
  'target-email': { type: 'email-addr' },
  'target-machine': { type: 'infrastructure', isSDO: true },
  'target-org': { type: 'identity', isSDO: true },
  'target-location': { type: 'location', isSDO: true },
  'target-external': { type: 'identity', isSDO: true },
  'btc': { type: 'user-account' },
  'dash': { type: 'user-account' },
  'xmr': { type: 'user-account' },
  'iban': { type: 'user-account' },
  'bic': { type: 'user-account' },
  'bank-account-nr': { type: 'user-account' },
  'aba-rtn': { type: 'user-account' },
  'bin': { type: 'user-account' },
  'cc-number': { type: 'user-account' },
  'prtn': { type: 'user-account' },
  'phone-number': { type: 'user-account' },
  'threat-actor': { type: 'threat-actor', isSDO: true },
  'campaign-name': { type: 'campaign', isSDO: true },
  'campaign-id': { type: 'campaign', isSDO: true },
  'malware-type': { type: 'malware', isSDO: true },
  'x509-fingerprint-sha1': { type: 'x509-certificate' },
  'x509-fingerprint-md5': { type: 'x509-certificate' },
  'x509-fingerprint-sha256': { type: 'x509-certificate' },
  'dns-soa-email': { type: 'email-addr' },
  'size-in-bytes': { type: 'observed-data', isSDO: true },
  'counter': { type: 'observed-data', isSDO: true },
  'integer': { type: 'observed-data', isSDO: true },
  'datetime': { type: 'observed-data', isSDO: true },
  'port': { type: 'network-traffic' },
  'mac-address': { type: 'mac-address' },
  'mac-eui-64': { type: 'mac-address' },
  'github-username': { type: 'user-account' },
  'github-repository': { type: 'url' },
  'github-organisation': { type: 'identity', isSDO: true },
  'jabber-id': { type: 'user-account' },
  'twitter-id': { type: 'user-account' },
  'dkim': { type: 'artifact' },
  'dkim-signature': { type: 'artifact' },
  'first-name': { type: 'identity', isSDO: true },
  'middle-name': { type: 'identity', isSDO: true },
  'last-name': { type: 'identity', isSDO: true },
  'full-name': { type: 'identity', isSDO: true },
  'date-of-birth': { type: 'identity', isSDO: true },
  'place-of-birth': { type: 'location', isSDO: true },
  'gender': { type: 'identity', isSDO: true },
  'passport-number': { type: 'identity', isSDO: true },
  'passport-country': { type: 'location', isSDO: true },
  'passport-expiration': { type: 'identity', isSDO: true },
  'redress-number': { type: 'identity', isSDO: true },
  'nationality': { type: 'identity', isSDO: true },
  'visa-number': { type: 'identity', isSDO: true },
  'issue-date-of-the-visa': { type: 'identity', isSDO: true },
  'primary-residence': { type: 'location', isSDO: true },
  'country-of-residence': { type: 'location', isSDO: true },
  'special-service-request': { type: 'identity', isSDO: true },
  'frequent-flyer-number': { type: 'identity', isSDO: true },
  'travel-details': { type: 'identity', isSDO: true },
  'payment-details': { type: 'identity', isSDO: true },
  'place-port-of-original-embarkation': { type: 'location', isSDO: true },
  'place-port-of-clearance': { type: 'location', isSDO: true },
  'place-port-of-onward-foreign-destination': { type: 'location', isSDO: true },
  'passenger-name-record-locator-number': { type: 'identity', isSDO: true },
  'mobile-application-id': { type: 'software' },
  'azure-application-id': { type: 'software' },
  'chrome-extension-id': { type: 'software' },
  'cortex': { type: 'indicator', isSDO: true },
  'boolean': { type: 'observed-data', isSDO: true },
  'anonymised': { type: 'observed-data', isSDO: true },
  'yara': { type: 'indicator', isSDO: true },
  'original-imported-file': { type: 'file' },
  'script': { type: 'tool' },
  'twitter-post': { type: 'observed-data' },
  'github-user': { type: 'user-account' },
  'pe-section': { type: 'file' },
  'pe': { type: 'file' },
  'virustotal-report': { type: 'observed-data' },
  'authenticode-signerinfo': { type: 'x509-certificate' },
  'ip-port': { type: 'network-traffic' },
  'passive-dns': { type: 'observed-data' },
  'user-action': { type: 'observed-data' },
  'domain-ip': { type: 'observed-data' },
  'malware-config': { type: 'malware' },
  'elf-section': { type: 'file' },
  'elf': { type: 'file' },
  'stix2-pattern': { type: 'indicator', isSDO: true },
  'android-app': { type: 'software' },
  'asn': { type: 'autonomous-system' },
  'geolocation': { type: 'location' },
  'float': { type: 'observed-data', isSDO: true },
  'double': { type: 'observed-data', isSDO: true },
  'hash': { type: 'file' }, // Generic hash, maps to file.hashes
  'hash-md5': { type: 'file' },
  'hash-sha1': { type: 'file' },
  'hash-sha256': { type: 'file' },
  'hash-sha512': { type: 'file' },
  'hash-sha3': { type: 'file' },
  'tor-hs': { type: 'url' }, // Tor hidden service URLs
  'tor-address': { type: 'url' },
  'pgp-key': { type: 'artifact' },
  'pgp-signature': { type: 'artifact' },
  'ssh-fingerprint': { type: 'artifact' },
  'certificate': { type: 'x509-certificate' },
  'x509': { type: 'x509-certificate' },
  'x509-serial': { type: 'x509-certificate' },
  'x509-subject': { type: 'x509-certificate' },
  'x509-issuer': { type: 'x509-certificate' },
  'x509-validity-not-before': { type: 'x509-certificate' },
  'x509-validity-not-after': { type: 'x509-certificate' },
  'x509-pubkey': { type: 'x509-certificate' },
  'dns': { type: 'domain-name' }, // DNS names
  'dns-query': { type: 'observed-data', isSDO: true },
  'dns-answer': { type: 'observed-data', isSDO: true },
  'whois-registrant': { type: 'identity', isSDO: true },
  'whois-registrant-email': { type: 'email-addr' },
  'whois-registrant-phone': { type: 'user-account' }, // Phone number in identity context
  'whois-registrant-name': { type: 'identity', isSDO: true },
  'whois-registrant-org': { type: 'identity', isSDO: true },
  'whois-registrar': { type: 'identity', isSDO: true },
  'whois-creation-date': { type: 'observed-data', isSDO: true },
  'whois-domain-status': { type: 'observed-data', isSDO: true },
  'whois-last-updated': { type: 'observed-data', isSDO: true },
  'cookie': { type: 'network-traffic' }, // HTTP cookie in network context
  'request-method': { type: 'network-traffic' },
  'request-uri': { type: 'url' },
  'http-status': { type: 'network-traffic' },
  'http-header': { type: 'network-traffic' },
  'http-body': { type: 'artifact' },
  'telegram-id': { type: 'user-account' },
  'discord-id': { type: 'user-account' },
  'matrix-id': { type: 'user-account' },
  'mastodon-id': { type: 'user-account' },
  'facebook-id': { type: 'user-account' },
  'linkedin-id': { type: 'user-account' },
  'instagram-id': { type: 'user-account' },
  'parler-id': { type: 'user-account' },
  'reddit-id': { type: 'user-account' },
  'tiktok-id': { type: 'user-account' },
  'signal-id': { type: 'user-account' },
  'whatsapp-id': { type: 'user-account' },
  'weixin-id': { type: 'user-account' },
  'vkontakte-id': { type: 'user-account' },
  'ip-address': { type: 'ipv4-addr' }, // Could also be ipv6-addr, context-dependent
  'ip-net': { type: 'ipv4-addr' }, // CIDR notation
  'ip-range': { type: 'observed-data', isSDO: true }, // Range needs context
  'email-cc': { type: 'email-addr' },
  'email-bcc': { type: 'email-addr' },
  'email-from': { type: 'email-addr' },
  'email-to': { type: 'email-addr' },
  'email-date': { type: 'email-message' },
  'email-in-reply-to': { type: 'email-message' },
  'email-references': { type: 'email-message' },
  'attachment-name': { type: 'file' },
  'attachment-type': { type: 'file' },
  'attachment-size': { type: 'file' },
  'attachment-md5': { type: 'file' },
  'attachment-sha1': { type: 'file' },
  'attachment-sha256': { type: 'file' },
  'attachment-content': { type: 'artifact' },
  'malware-name': { type: 'malware', isSDO: true },
  'malware-family': { type: 'malware', isSDO: true },
  'tool-name': { type: 'tool', isSDO: true },
  'tool-version': { type: 'tool', isSDO: true },
  'tool-alias': { type: 'tool', isSDO: true },
  'course-of-action': { type: 'course-of-action', isSDO: true },
  'attack-pattern': { type: 'attack-pattern', isSDO: true },
  'identity-contact': { type: 'identity', isSDO: true },
  'identity-sector': { type: 'identity', isSDO: true },
  'identity-description': { type: 'identity', isSDO: true },
  'location-city': { type: 'location', isSDO: true },
  'location-country': { type: 'location', isSDO: true },
  'location-region': { type: 'location', isSDO: true },
  'location-postal-code': { type: 'location', isSDO: true },
  'location-latitude': { type: 'location', isSDO: true },
  'location-longitude': { type: 'location', isSDO: true },
  'process-name': { type: 'process' },
  'process-path': { type: 'process' },
  'process-pid': { type: 'process' },
  'process-parent-pid': { type: 'process' },
  'process-created': { type: 'process' },
  'registry-key-created': { type: 'windows-registry-key' },
  'registry-key-modified': { type: 'windows-registry-key' },
  'mutex-name': { type: 'mutex' },
  'pipe-name': { type: 'file' },
  'crypto-address': { type: 'user-account' },
  'crypto-wallet': { type: 'user-account' },
  'exploit-kit': { type: 'malware', isSDO: true },
  'cve': { type: 'vulnerability', isSDO: true },
  'cvss-score': { type: 'vulnerability', isSDO: true },
  'cvss-vector': { type: 'vulnerability', isSDO: true },
  'sigma-rule': { type: 'indicator', isSDO: true },
  'suricata': { type: 'indicator', isSDO: true },
  'elk-id': { type: 'observed-data', isSDO: true },
  'splunk-id': { type: 'observed-data', isSDO: true },
  'query': { type: 'observed-data', isSDO: true },
  'search-term': { type: 'observed-data', isSDO: true },
  'threat-intel-report': { type: 'report', isSDO: true },
  'traffic-pattern': { type: 'indicator', isSDO: true },
  'traffic-volume': { type: 'observed-data', isSDO: true },
  'packet': { type: 'network-traffic' },
  'protocol': { type: 'network-traffic' },
  'source-port': { type: 'network-traffic' },
  'destination-port': { type: 'network-traffic' },
  'network-connection': { type: 'network-traffic' },
  'network-protocol': { type: 'network-traffic' },
  'network-service': { type: 'network-traffic' },
  'service-name': { type: 'network-traffic' },
  'service-port': { type: 'network-traffic' },
  'user-id': { type: 'user-account' },
  'group-id': { type: 'user-account' },
  'account-login': { type: 'user-account' },
  'account-type': { type: 'user-account' },
  'account-created': { type: 'user-account' },
  'account-modified': { type: 'user-account' },
  'credential': { type: 'user-account' },
  'auth-token': { type: 'user-account' },
  'api-key': { type: 'user-account' },
  'signature': { type: 'artifact' },
  'command': { type: 'observed-data', isSDO: true },
  'command-line': { type: 'process' },
  'script-name': { type: 'tool', isSDO: true },
  'script-path': { type: 'tool', isSDO: true },
  'vulnerability-description': { type: 'vulnerability', isSDO: true },
  'vulnerability-published': { type: 'vulnerability', isSDO: true },
  'vulnerability-updated': { type: 'vulnerability', isSDO: true },
  'vulnerability-reference': { type: 'vulnerability', isSDO: true },
  'threat-actor-alias': { type: 'threat-actor', isSDO: true },
  'threat-actor-role': { type: 'threat-actor', isSDO: true },
  'threat-actor-sophistication': { type: 'threat-actor', isSDO: true },
  'threat-actor-type': { type: 'threat-actor', isSDO: true },
  'campaign-description': { type: 'campaign', isSDO: true },
  'campaign-start-date': { type: 'campaign', isSDO: true },
  'campaign-end-date': { type: 'campaign', isSDO: true },
  'incident': { type: 'incident', isSDO: true },
  'incident-description': { type: 'incident', isSDO: true },
  'incident-type': { type: 'incident', isSDO: true },
  'incident-reported': { type: 'incident', isSDO: true },
  'data': { type: 'artifact' },
  'data-type': { type: 'artifact' },
  'data-encoding': { type: 'artifact' },
  'data-size': { type: 'artifact' },
  'reference': { type: 'note', isSDO: true },
  'note': { type: 'note', isSDO: true },
  'opinion': { type: 'opinion', isSDO: true },
  'relationship': { type: 'relationship', isSDO: true },
  'sighting': { type: 'sighting', isSDO: true },
  'marking-definition': { type: 'marking-definition', isSDO: true },
  'tlp': { type: 'marking-definition', isSDO: true },
  'pap': { type: 'marking-definition', isSDO: true },
  'confidence': { type: 'observed-data', isSDO: true },
  'context': { type: 'note', isSDO: true },
  'category': { type: 'note', isSDO: true },
  'tag': { type: 'marking-definition', isSDO: true },
  'cluster': { type: 'observed-data', isSDO: true },
  'galaxy': { type: 'observed-data', isSDO: true },
  'object': { type: 'observed-data', isSDO: true },
  'object-reference': { type: 'relationship', isSDO: true },
  'object-template': { type: 'observed-data', isSDO: true },
  'workflow': { type: 'observed-data', isSDO: true },

  // Fallback for unknown types
  default: { type: 'observed-data', isSDO: true },
};

// STIX Type Lists
const STIX_SCO_TYPES: StixType[] = [
  'artifact',
  'autonomous-system',
  'directory',
  'domain-name',
  'email-addr',
  'email-message',
  'file',
  'ipv4-addr',
  'ipv6-addr',
  'mac-address',
  'mutex',
  'network-traffic',
  'process',
  'software',
  'url',
  'user-account',
  'windows-registry-key',
  'x509-certificate',
];
const STIX_SDO_TYPES: StixType[] = [
  'attack-pattern',
  'campaign',
  'course-of-action',
  'grouping',
  'identity',
  'indicator',
  'infrastructure',
  'intrusion-set',
  'location',
  'malware',
  'malware-analysis',
  'note',
  'observed-data',
  'opinion',
  'report',
  'threat-actor',
  'tool',
  'vulnerability',
  
];
const STIX_RELATIONSHIP_TYPES: StixType[] = ['relationship', 'sighting'];

function* processMispObject(mispObject: any, eventTimestamp: number): Generator<GenericStixObject, void, unknown> {
  console.log(`Processing MISP object: ${JSON.stringify(mispObject, null, 2).substring(0, 500)}`);
  const timestamp = mispObject.timestamp || eventTimestamp;
  const tlpMarking = createTLPMarking('white', timestamp);
  yield tlpMarking;

  try {
    if (!mispObject.name || !mispObject.uuid) {
      console.warn(`Skipping MISP object with missing name or uuid: ${JSON.stringify(mispObject)}`);
      return;
    }

    switch (mispObject.name) {
      case 'file':
        const fileObj: GenericStixObject = {
          id: generateStixId('file', mispObject.uuid),
          type: 'file',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'filename')?.value,
          hashes: {
            MD5: mispObject.attributes?.find((a: any) => a.object_relation === 'md5')?.value,
            'SHA-1': mispObject.attributes?.find((a: any) => a.object_relation === 'sha1')?.value,
            'SHA-256': mispObject.attributes?.find((a: any) => a.object_relation === 'sha256')?.value,
            'SHA-512': mispObject.attributes?.find((a: any) => a.object_relation === 'sha512')?.value,
            SSDEEP: mispObject.attributes?.find((a: any) => a.object_relation === 'ssdeep')?.value,
          },
          size: parseInt(mispObject.attributes?.find((a: any) => a.object_relation === 'size-in-bytes')?.value, 10) || undefined,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'file'],
          object_marking_refs: [tlpMarking.id],
        };
        yield fileObj;
        break;

      case 'email':
        const emailMessageObj: GenericStixObject = {
          id: generateStixId('email-message', mispObject.uuid),
          type: 'email-message',
          spec_version: STIX_VERSION,
          subject: mispObject.attributes?.find((a: any) => a.object_relation === 'subject')?.value,
          body: mispObject.attributes?.find((a: any) => a.object_relation === 'message-body')?.value,
          from_ref: mispObject.attributes?.find((a: any) => a.object_relation === 'from' && isValidEmail(a.value))?.value
            ? generateStixId('email-addr', mispObject.uuid + '-from')
            : undefined,
          to_refs: mispObject.attributes?.find((a: any) => a.object_relation === 'to' && isValidEmail(a.value))?.value
            ? [generateStixId('email-addr', mispObject.uuid + '-to')]
            : undefined,
          date: mispObject.attributes?.find((a: any) => a.object_relation === 'send-date')?.value
            ? moment(mispObject.attributes?.find((a: any) => a.object_relation === 'send-date')?.value).toISOString()
            : undefined,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'email'],
          object_marking_refs: [tlpMarking.id],
        };
        
        if (emailMessageObj.from_ref) {
          const fromAddrObj: GenericStixObject = {
            id: emailMessageObj.from_ref,
            type: 'email-addr',
            spec_version: STIX_VERSION,
            value: mispObject.attributes?.find((a: any) => a.object_relation === 'from')?.value,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'email'],
            object_marking_refs: [tlpMarking.id],
          };
          yield fromAddrObj;
        }
        
        if (emailMessageObj.to_refs?.length) {
          const toAddrObj: GenericStixObject = {
            id: emailMessageObj.to_refs[0],
            type: 'email-addr',
            spec_version: STIX_VERSION,
            value: mispObject.attributes?.find((a: any) => a.object_relation === 'to')?.value,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'email'],
            object_marking_refs: [tlpMarking.id],
          };
          yield toAddrObj;
        }
        
        yield emailMessageObj;
        break;

      case 'network-traffic':
        const srcIp = mispObject.attributes?.find((a: any) => a.object_relation === 'ip-src')?.value;
        const dstIp = mispObject.attributes?.find((a: any) => a.object_relation === 'ip-dst')?.value;
        const networkTrafficObj: GenericStixObject = {
          id: generateStixId('network-traffic', mispObject.uuid),
          type: 'network-traffic',
          spec_version: STIX_VERSION,
          src_ref: srcIp && isValidIp(srcIp) ? generateStixId(srcIp.includes(':') ? 'ipv6-addr' : 'ipv4-addr', mispObject.uuid + '-src') : undefined,
          dst_ref: dstIp && isValidIp(dstIp) ? generateStixId(dstIp.includes(':') ? 'ipv6-addr' : 'ipv4-addr', mispObject.uuid + '-dst') : undefined,
          src_port: parseInt(mispObject.attributes?.find((a: any) => a.object_relation === 'port-src')?.value, 10) || undefined,
          dst_port: parseInt(mispObject.attributes?.find((a: any) => a.object_relation === 'port-dst')?.value, 10) || undefined,
          protocols: [mispObject.attributes?.find((a: any) => a.object_relation === 'protocol')?.value || 'tcp'],
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'network-connection'],
          object_marking_refs: [tlpMarking.id],
        };
        
        if (networkTrafficObj.src_ref) {
          const srcIpObj: GenericStixObject = {
            id: networkTrafficObj.src_ref,
            type: srcIp.includes(':') ? 'ipv6-addr' : 'ipv4-addr',
            spec_version: STIX_VERSION,
            value: srcIp,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'network-connection'],
            object_marking_refs: [tlpMarking.id],
          };
          yield srcIpObj;
        }
        
        if (networkTrafficObj.dst_ref) {
          const dstIpObj: GenericStixObject = {
            id: networkTrafficObj.dst_ref,
            type: dstIp.includes(':') ? 'ipv6-addr' : 'ipv4-addr',
            spec_version: STIX_VERSION,
            value: dstIp,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'network-connection'],
            object_marking_refs: [tlpMarking.id],
          };
          yield dstIpObj;
        }
        
        yield networkTrafficObj;
        break;

      case 'process':
        const processObj: GenericStixObject = {
          id: generateStixId('process', mispObject.uuid),
          type: 'process',
          spec_version: STIX_VERSION,
          pid: parseInt(mispObject.attributes?.find((a: any) => a.object_relation === 'pid')?.value, 10) || undefined,
          command_line: mispObject.attributes?.find((a: any) => a.object_relation === 'command-line')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'process'],
          object_marking_refs: [tlpMarking.id],
        };
        yield processObj;
        break;

      case 'windows-registry-key':
        const registryKeyObj: GenericStixObject = {
          id: generateStixId('windows-registry-key', mispObject.uuid),
          type: 'windows-registry-key',
          spec_version: STIX_VERSION,
          key: mispObject.attributes?.find((a: any) => a.object_relation === 'key')?.value,
          values: mispObject.attributes?.filter((a: any) => a.object_relation === 'value')?.map((v: any) => ({ name: v.value })) || [],
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'registry-key'],
          object_marking_refs: [tlpMarking.id],
        };
        yield registryKeyObj;
        break;

      case 'url':
        const urlValue = mispObject.attributes?.find((a: any) => a.object_relation === 'url')?.value;
        if (urlValue && isValidUrl(urlValue)) {
          const urlObj: GenericStixObject = {
            id: generateStixId('url', mispObject.uuid),
            type: 'url',
            spec_version: STIX_VERSION,
            value: urlValue,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'url'],
            object_marking_refs: [tlpMarking.id],
          };
          yield urlObj;
        }
        break;

      case 'domain-name':
        const domainValue = mispObject.attributes?.find((a: any) => a.object_relation === 'domain')?.value;
        const ipValue = mispObject.attributes?.find((a: any) => a.object_relation === 'ip')?.value;
        if (domainValue && isValidDomain(domainValue) && ipValue && isValidIp(ipValue)) {
          const domainObj: GenericStixObject = {
            id: generateStixId('domain-name', mispObject.uuid + '-domain'),
            type: 'domain-name',
            spec_version: STIX_VERSION,
            value: domainValue,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'domain-ip'],
            object_marking_refs: [tlpMarking.id],
          };
          const ipObj: GenericStixObject = {
            id: generateStixId(ipValue.includes(':') ? 'ipv6-addr' : 'ipv4-addr', mispObject.uuid + '-ip'),
            type: ipValue.includes(':') ? 'ipv6-addr' : 'ipv4-addr',
            spec_version: STIX_VERSION,
            value: ipValue,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'domain-ip'],
            object_marking_refs: [tlpMarking.id],
          };
          const relationshipObj: GenericStixObject = createRelationship(
            domainObj.id,
            ipObj.id,
            'resolves-to',
            timestamp,
            'Domain resolves to IP address',
          );
          yield domainObj;
          yield ipObj;
          yield relationshipObj;
        }
        break;

      case 'autonomous-system':
        const asNumber = mispObject.attributes?.find((a: any) => a.object_relation === 'asn')?.value;
        if (asNumber) {
          const asObj: GenericStixObject = {
            id: generateStixId('autonomous-system', mispObject.uuid),
            type: 'autonomous-system',
            spec_version: STIX_VERSION,
            number: parseInt(asNumber.replace('AS', ''), 10) || 0,
            name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'autonomous-system'],
            object_marking_refs: [tlpMarking.id],
          };
          yield asObj;
        }
        break;

      case 'user-account':
        const userAccountObj: GenericStixObject = {
          id: generateStixId('user-account', mispObject.uuid),
          type: 'user-account',
          spec_version: STIX_VERSION,
          user_id: mispObject.attributes?.find((a: any) => a.object_relation === 'username')?.value,
          account_type: mispObject.attributes?.find((a: any) => a.object_relation === 'account-type')?.value || 'unknown',
          display_name: mispObject.attributes?.find((a: any) => a.object_relation === 'display-name')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'user-account'],
          object_marking_refs: [tlpMarking.id],
        };
        yield userAccountObj;
        break;

      case 'x509':
        const x509Obj: GenericStixObject = {
          id: generateStixId('x509-certificate', mispObject.uuid),
          type: 'x509-certificate',
          spec_version: STIX_VERSION,
          issuer: mispObject.attributes?.find((a: any) => a.object_relation === 'issuer')?.value,
          serial_number: mispObject.attributes?.find((a: any) => a.object_relation === 'serial-number')?.value,
          hashes: {
            MD5: mispObject.attributes?.find((a: any) => a.object_relation === 'md5')?.value,
            'SHA-1': mispObject.attributes?.find((a: any) => a.object_relation === 'sha1')?.value,
            'SHA-256': mispObject.attributes?.find((a: any) => a.object_relation === 'sha256')?.value,
          },
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'x509-certificate'],
          object_marking_refs: [tlpMarking.id],
        };
        yield x509Obj;
        break;

      case 'mutex':
        const mutexObj: GenericStixObject = {
          id: generateStixId('mutex', mispObject.uuid),
          type: 'mutex',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'mutex'],
          object_marking_refs: [tlpMarking.id],
        };
        yield mutexObj;
        break;

      case 'software':
        const softwareObj: GenericStixObject = {
          id: generateStixId('software', mispObject.uuid),
          type: 'software',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value,
          version: mispObject.attributes?.find((a: any) => a.object_relation === 'version')?.value,
          vendor: mispObject.attributes?.find((a: any) => a.object_relation === 'vendor')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'software'],
          object_marking_refs: [tlpMarking.id],
        };
        yield softwareObj;
        break;

      case 'directory':
        const directoryObj: GenericStixObject = {
          id: generateStixId('directory', mispObject.uuid),
          type: 'directory',
          spec_version: STIX_VERSION,
          path: mispObject.attributes?.find((a: any) => a.object_relation === 'path')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'directory'],
          object_marking_refs: [tlpMarking.id],
        };
        yield directoryObj;
        break;

      case 'mac-address':
        const macValue = mispObject.attributes?.find((a: any) => a.object_relation === 'mac-address')?.value;
        if (macValue && isValidMacAddress(macValue)) {
          const macObj: GenericStixObject = {
            id: generateStixId('mac-address', mispObject.uuid),
            type: 'mac-address',
            spec_version: STIX_VERSION,
            value: macValue,
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-object', 'mac-address'],
            object_marking_refs: [tlpMarking.id],
          };
          yield macObj;
        }
        break;

      case 'artifact':
        const artifactObj: GenericStixObject = {
          id: generateStixId('artifact', mispObject.uuid),
          type: 'artifact',
          spec_version: STIX_VERSION,
          payload_bin: mispObject.attributes?.find((a: any) => a.object_relation === 'data')?.value,
          mime_type: mispObject.attributes?.find((a: any) => a.object_relation === 'mime-type')?.value || 'application/octet-stream',
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'artifact'],
          object_marking_refs: [tlpMarking.id],
        };
        yield artifactObj;
        break;

      case 'vulnerability':
        const vulnerabilityObj: GenericStixObject = {
          id: generateStixId('vulnerability', mispObject.uuid),
          type: 'vulnerability',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'id')?.value || 'Unknown Vulnerability',
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'vulnerability'],
          object_marking_refs: [tlpMarking.id],
        };
        yield vulnerabilityObj;
        break;

      case 'malware':
        const malwareObj: GenericStixObject = {
          id: generateStixId('malware', mispObject.uuid),
          type: 'malware',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Malware',
          malware_types: [mispObject.attributes?.find((a: any) => a.object_relation === 'type')?.value || 'unknown'],
          is_family: false,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'malware'],
          object_marking_refs: [tlpMarking.id],
        };
        yield malwareObj;
        break;

      case 'threat-actor':
        const threatActorObj: GenericStixObject = {
          id: generateStixId('threat-actor', mispObject.uuid),
          type: 'threat-actor',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Threat Actor',
          threat_actor_types: [mispObject.attributes?.find((a: any) => a.object_relation === 'type')?.value || 'unknown'],
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'threat-actor'],
          object_marking_refs: [tlpMarking.id],
        };
        yield threatActorObj;
        break;

      case 'campaign':
        const campaignObj: GenericStixObject = {
          id: generateStixId('campaign', mispObject.uuid),
          type: 'campaign',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Campaign',
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'campaign'],
          object_marking_refs: [tlpMarking.id],
        };
        yield campaignObj;
        break;

      case 'attack-pattern':
        const attackPatternObj: GenericStixObject = {
          id: generateStixId('attack-pattern', mispObject.uuid),
          type: 'attack-pattern',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Attack Pattern',
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'attack-pattern'],
          object_marking_refs: [tlpMarking.id],
        };
        yield attackPatternObj;
        break;

      case 'course-of-action':
        const courseOfActionObj: GenericStixObject = {
          id: generateStixId('course-of-action', mispObject.uuid),
          type: 'course-of-action',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Course of Action',
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'course-of-action'],
          object_marking_refs: [tlpMarking.id],
        };
        yield courseOfActionObj;
        break;

      case 'identity':
        const identityObj: GenericStixObject = {
          id: generateStixId('identity', mispObject.uuid),
          type: 'identity',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Identity',
          identity_class: mispObject.attributes?.find((a: any) => a.object_relation === 'type')?.value === 'individual' ? 'individual' : 'organization',
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'identity'],
          object_marking_refs: [tlpMarking.id],
        };
        yield identityObj;
        break;

      case 'infrastructure':
        const infrastructureObj: GenericStixObject = {
          id: generateStixId('infrastructure', mispObject.uuid),
          type: 'infrastructure',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Infrastructure',
          infrastructure_types: [mispObject.attributes?.find((a: any) => a.object_relation === 'type')?.value || 'unknown'],
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'infrastructure'],
          object_marking_refs: [tlpMarking.id],
        };
        yield infrastructureObj;
        break;

      case 'intrusion-set':
        const intrusionSetObj: GenericStixObject = {
          id: generateStixId('intrusion-set', mispObject.uuid),
          type: 'intrusion-set',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Intrusion Set',
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'intrusion-set'],
          object_marking_refs: [tlpMarking.id],
        };
        yield intrusionSetObj;
        break;

      case 'location':
        const locationObj: GenericStixObject = {
          id: generateStixId('location', mispObject.uuid),
          type: 'location',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value,
          country: mispObject.attributes?.find((a: any) => a.object_relation === 'country')?.value,
          city: mispObject.attributes?.find((a: any) => a.object_relation === 'city')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'location'],
          object_marking_refs: [tlpMarking.id],
        };
        yield locationObj;
        break;

      case 'tool':
        const toolObj: GenericStixObject = {
          id: generateStixId('tool', mispObject.uuid),
          type: 'tool',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Tool',
          tool_types: [mispObject.attributes?.find((a: any) => a.object_relation === 'type')?.value || 'unknown'],
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'tool'],
          object_marking_refs: [tlpMarking.id],
        };
        yield toolObj;
        break;

      case 'indicator':
        const indicatorValue = mispObject.attributes?.find((a: any) => a.object_relation === 'pattern')?.value;
        if (!indicatorValue) {
          console.warn(`Indicator object missing pattern: ${JSON.stringify(mispObject)}`);
        }
        const indicatorObj: GenericStixObject = {
          id: generateStixId('indicator', mispObject.uuid),
          type: 'indicator',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Indicator',
          pattern: indicatorValue || 'unknown',
          pattern_type: 'stix',
          valid_from: moment(timestamp * 1000).toISOString(),
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'indicator'],
          object_marking_refs: [tlpMarking.id],
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value || 'MISP indicator object',
        };
        yield indicatorObj;
        break;

      case 'observed-data':
        const observedDataObj: GenericStixObject = {
          id: generateStixId('observed-data', mispObject.uuid),
          type: 'observed-data',
          spec_version: STIX_VERSION,
          number_observed: parseInt(mispObject.attributes?.find((a: any) => a.object_relation === 'count')?.value, 10) || 1,
          first_observed: moment(timestamp * 1000).toISOString(),
          last_observed: moment(timestamp * 1000).toISOString(),
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'observed-data'],
          object_marking_refs: [tlpMarking.id],
        };
        yield observedDataObj;
        break;

      case 'report':
        const reportObj: GenericStixObject = {
          id: generateStixId('report', mispObject.uuid),
          type: 'report',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'title')?.value || 'Unknown Report',
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value,
          published: moment(timestamp * 1000).toISOString(),
          object_refs: [],
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'report'],
          object_marking_refs: [tlpMarking.id],
        };
        yield reportObj;
        break;

      case 'note':
        const noteObj: GenericStixObject = {
          id: generateStixId('note', mispObject.uuid),
          type: 'note',
          spec_version: STIX_VERSION,
          content: mispObject.attributes?.find((a: any) => a.object_relation === 'content')?.value || 'No content provided',
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'note'],
          object_marking_refs: [tlpMarking.id],
        };
        yield noteObj;
        break;

      case 'opinion':
        const opinionObj: GenericStixObject = {
          id: generateStixId('opinion', mispObject.uuid),
          type: 'opinion',
          spec_version: STIX_VERSION,
          explanation: mispObject.attributes?.find((a: any) => a.object_relation === 'explanation')?.value,
          opinion: mispObject.attributes?.find((a: any) => a.object_relation === 'opinion')?.value || 'unknown',
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'opinion'],
          object_marking_refs: [tlpMarking.id],
        };
        yield opinionObj;
        break;

      case 'grouping':
        const groupingObj: GenericStixObject = {
          id: generateStixId('grouping', mispObject.uuid),
          type: 'grouping',
          spec_version: STIX_VERSION,
          name: mispObject.attributes?.find((a: any) => a.object_relation === 'name')?.value || 'Unknown Grouping',
          description: mispObject.attributes?.find((a: any) => a.object_relation === 'description')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'grouping'],
          object_marking_refs: [tlpMarking.id],
        };
        yield groupingObj;
        break;

      case 'malware-analysis':
        const malwareAnalysisObj: GenericStixObject = {
          id: generateStixId('malware-analysis', mispObject.uuid),
          type: 'malware-analysis',
          spec_version: STIX_VERSION,
          product: mispObject.attributes?.find((a: any) => a.object_relation === 'product')?.value || 'Unknown',
          result: mispObject.attributes?.find((a: any) => a.object_relation === 'result')?.value,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', 'malware-analysis'],
          object_marking_refs: [tlpMarking.id],
        };
        yield malwareAnalysisObj;
        break;

      default:
        console.warn(`Unsupported MISP object type: ${mispObject.name}`);
        const observedDataFallback: GenericStixObject = {
          id: generateStixId('observed-data', mispObject.uuid),
          type: 'observed-data',
          spec_version: STIX_VERSION,
          number_observed: 1,
          first_observed: moment(timestamp * 1000).toISOString(),
          last_observed: moment(timestamp * 1000).toISOString(),
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: ['misp-object', mispObject.name, 'fallback'],
          object_marking_refs: [tlpMarking.id],
        };
        yield observedDataFallback;
        break;
    }
  } catch (error) {
    console.error(`Error processing MISP object ${mispObject.uuid || 'unknown'}: ${(error as Error).message}`);
  }
}

export function* processMispData(raw: any): Generator<GenericStixObject, void, unknown> {
  try {
    console.log(`Processing MISP raw data: ${JSON.stringify(raw, null, 2).substring(0, 1000)}`);
    const isEvent = !!raw.Event;
    const event = raw.Event || raw;
    const attributes = event.Attribute || raw.response?.Attribute || [];
    const objects = event.Object || [];
    const objectReferences = event.ObjectReference || [];
    console.log(`Attributes count: ${attributes.length}, Objects count: ${objects.length}, ObjectReferences count: ${objectReferences.length}`);
    const eventTimestamp = event.timestamp || Math.floor(Date.now() / 1000);
    const stixObjectMap: Record<string, GenericStixObject> = {};
    const createdRelationships: Set<string> = new Set();
    let report: GenericStixObject | undefined;

    const validRelationships = new Map<string, Set<string>>([
      ['attack-pattern', new Set(['delivers', 'targets', 'uses'])],
      ['campaign', new Set(['attributed-to', 'compromises', 'originates-from', 'targets', 'uses'])],
      ['course-of-action', new Set(['investigates', 'mitigates'])],
      ['identity', new Set(['located-at'])],
      ['indicator', new Set(['indicates', 'based-on'])],
      ['infrastructure', new Set(['communicates-with', 'consists-of', 'controls', 'delivers', 'has', 'hosts', 'located-at', 'uses'])],
      ['intrusion-set', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'originates-from', 'targets', 'uses'])],
      ['malware', new Set(['authored-by', 'beacons-to', 'exfiltrate-to', 'communicates-with', 'controls', 'downloads', 'drops', 'exploits', 'originates-from', 'targets', 'uses', 'variant-of'])],
      ['malware-analysis', new Set(['characterizes', 'analysis-of', 'static-analysis-of', 'dynamic-analysis-of'])],
      ['threat-actor', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'impersonates', 'located-at', 'targets', 'uses'])],
      ['tool', new Set(['delivers', 'drops', 'has', 'targets'])],
    ]);
    
    const validTargets = new Map<string, Set<string>>([
      ['delivers', new Set(['malware'])],
      ['targets', new Set(['identity', 'location', 'vulnerability', 'infrastructure'])],
      ['uses', new Set(['attack-pattern', 'infrastructure', 'malware', 'tool'])],
      ['attributed-to', new Set(['intrusion-set', 'threat-actor', 'identity'])],
      ['compromises', new Set(['infrastructure'])],
      ['originates-from', new Set(['location'])],
      ['investigates', new Set(['indicator'])],
      ['mitigates', new Set(['attack-pattern', 'indicator', 'malware', 'tool', 'vulnerability'])],
      ['located-at', new Set(['location'])],
      ['indicates', new Set(['attack-pattern', 'campaign', 'infrastructure', 'intrusion-set', 'malware', 'threat-actor', 'tool'])],
      ['based-on', new Set([
        'observed-data',
        'ipv4-addr',
        'ipv6-addr',
        'domain-name',
        'url',
        'email-addr',
        'file',
        'mutex',
        'windows-registry-key',
        'x509-certificate',
        'autonomous-system',
        'network-traffic',
        'software',
        'user-account',
        'mac-addr',
        'process',
        'directory',
        'artifact'
      ])],
      ['communicates-with', new Set(['infrastructure'])],
      ['consists-of', new Set(['infrastructure'])],
      ['controls', new Set(['infrastructure', 'malware'])],
      ['has', new Set(['vulnerability'])],
      ['hosts', new Set(['infrastructure', 'malware'])],
      ['authored-by', new Set(['threat-actor'])],
      ['beacons-to', new Set(['infrastructure'])],
      ['exfiltrate-to', new Set(['infrastructure'])],
      ['downloads', new Set(['malware', 'tool'])],
      ['drops', new Set(['malware', 'tool'])],
      ['exploits', new Set(['vulnerability'])],
      ['variant-of', new Set(['malware'])],
      ['characterizes', new Set(['malware'])],
      ['analysis-of', new Set(['malware'])],
      ['static-analysis-of', new Set(['malware'])],
      ['dynamic-analysis-of', new Set(['malware'])],
      ['owns', new Set(['infrastructure'])],
      ['impersonates', new Set(['identity'])],
    ]);

    // Process Galaxy Clusters
    if (event.Galaxy) {
      for (const galaxy of event.Galaxy) {
        if (galaxy.GalaxyCluster) {
          for (const cluster of galaxy.GalaxyCluster) {
            let stixType: StixType = 'intrusion-set';
            if (cluster.type.includes('attack-pattern') || cluster.type.includes('mitre-attack-pattern')) stixType = 'attack-pattern';
            else if (cluster.type.includes('malware')) stixType = 'malware';
            else if (cluster.type.includes('tool')) stixType = 'tool';
            else if (cluster.type.includes('threat-actor')) stixType = 'threat-actor';
            else if (cluster.type.includes('campaign')) stixType = 'campaign';

            const tlpMarking = createTLPMarking('white', eventTimestamp);
            const galaxyObj: GenericStixObject = {
              id: generateStixId(stixType, cluster.uuid),
              type: stixType,
              spec_version: STIX_VERSION,
              name: cluster.value || 'Unknown Galaxy Cluster',
              description: cluster.description || '',
              labels: ['misp-galaxy', galaxy.name || 'unknown'],
              external_references: [
                {
                  source_name: 'MISP Galaxy',
                  external_id: cluster.uuid,
                  url: `https://github.com/MISP/misp-galaxy/blob/main/clusters/${galaxy.name || 'unknown'}.json`,
                },
              ],
              created: moment(cluster.timestamp * 1000).toISOString(),
              modified: moment(cluster.timestamp * 1000).toISOString(),
              object_marking_refs: [tlpMarking.id],
            };

            if (stixType === 'attack-pattern') {
              const mitreId = cluster.value?.match(/T\d{4}/)?.[0];
              if (mitreId) {
                galaxyObj.external_references.push({
                  source_name: 'mitre-attack',
                  external_id: mitreId,
                  url: `https://attack.mitre.org/techniques/${mitreId}/`,
                });
              }
            }

            yield tlpMarking;
            yield galaxyObj;
            stixObjectMap[cluster.uuid] = galaxyObj;
          }
        }
      }
    }

    // Initialize STIX Report for the MISP Event
    if (isEvent) {
      const tlpMarking = createTLPMarking('white', eventTimestamp);
      const reportId = generateStixId('report', event.uuid || uuidv5('misp-event', NAMESPACE));
      report = {
        id: reportId,
        type: 'report',
        spec_version: STIX_VERSION,
        name: event.info || 'MISP Event Report',
        description: event.extended_info || event.info || 'Report generated from MISP event',
        report_types: event.Tag?.filter((t: any) => t.name.startsWith('report-type:'))
          .map((t: any) => t.name.split(':')[1]) || ['threat-report'],
        published: event.publish_timestamp
          ? moment(event.publish_timestamp * 1000).toISOString()
          : moment(event.date * 1000).toISOString(),
        created: moment(event.date * 1000).toISOString(),
        modified: moment(eventTimestamp * 1000).toISOString(),
        labels: ['misp-event', ...(event.Tag?.map((t: any) => t.name) || [])],
        confidence: event.analysis ? mapMispAnalysisToConfidence(event.analysis) : undefined,
        lang: event.lang || 'en',
        external_references: event.uuid
          ? [{
              source_name: 'MISP',
              external_id: event.uuid,
              url: `${MISP_BASE_URL}/events/${event.uuid}`,
            }]
          : [],
        object_marking_refs: [tlpMarking.id],
        object_refs: [],
      };
      yield tlpMarking; // Yield TLP marking for the report
      stixObjectMap[event.uuid || 'misp-event'] = report;
    }

    // Process Attributes
    for (const attr of attributes) {
      try {
        console.log(`Processing MISP attribute: ${JSON.stringify(attr, null, 2)}`);
        const mapping = MISP_TO_STIX_MAPPING[attr.type ] || MISP_TO_STIX_MAPPING.default ;
        const stixType: StixType = mapping.type;
        const isSDO = mapping.isSDO || false;
        const value = attr.value || '';
        const category = attr.category || 'Other';
        const toIds = attr.to_ids ?? false;
        const timestamp = attr.timestamp || eventTimestamp;
        const attrUuid = attr.uuid || uuidv5(`${value}_${stixType}`, NAMESPACE);

        if (!value) {
          console.warn(`Missing value for MISP attribute: ${JSON.stringify(attr)}`);
          const tlpMarking = createTLPMarking('white', timestamp);
          const fallbackObj: GenericStixObject = {
            id: generateStixId('observed-data', attrUuid),
            type: 'observed-data',
            spec_version: STIX_VERSION,
            number_observed: 1,
            first_observed: moment(timestamp * 1000).toISOString(),
            last_observed: moment(timestamp * 1000).toISOString(),
            created: moment(timestamp * 1000).toISOString(),
            modified: moment(timestamp * 1000).toISOString(),
            labels: ['misp-attribute', 'fallback'],
            description: `Fallback for MISP attribute with missing value: ${attr.type}`,
            object_marking_refs: [tlpMarking.id],
          };
          yield tlpMarking;
          yield fallbackObj;
          stixObjectMap[attrUuid] = fallbackObj;
          if (report) report.object_refs.push(fallbackObj.id);
          continue;
        }

        const compositeValues = attr.type.includes('|') ? value.split('|').map((v: string) => v.trim()) : undefined;
        const tlpMarking = createTLPMarking('white', timestamp);
        const baseObject: GenericStixObject = {
          id: generateStixId(stixType, attrUuid),
          type: stixType,
          spec_version: STIX_VERSION,
          created: moment(timestamp * 1000).toISOString(),
          modified: moment(timestamp * 1000).toISOString(),
          labels: [category.toLowerCase(), 'misp-attribute', ...(attr.Tag?.map((t: any) => t.name) || [])],
          external_references: attrUuid
            ? [{
                source_name: 'MISP',
                external_id: attrUuid,
                url: `${MISP_BASE_URL}/attributes/${attrUuid}`,
              }]
            : [],
          object_marking_refs: [tlpMarking.id],
        };

        let objectToAdd: GenericStixObject | null = null;
        if (isSDO) {
          objectToAdd = {
            ...baseObject,
            name: value,
            description: attr.comment || `MISP ${stixType} attribute`,
          };
          if (stixType === 'indicator') {
            if (!value) {
              console.warn(`Skipping indicator with empty value: ${JSON.stringify(attr)}`);
              objectToAdd = {
                ...baseObject,
                type: 'observed-data',
                number_observed: 1,
                first_observed: baseObject.created,
                last_observed: baseObject.modified,
                description: `Fallback for MISP indicator with empty value: ${attr.type}`,
              };
            } else {
              objectToAdd.pattern = attr.pattern || `[${attr.type}:value = '${value.replace(/'/g, "\\'")}']`;
              objectToAdd.pattern_type = 'stix';
              objectToAdd.valid_from = moment(timestamp * 1000).toISOString();
            }
          } else if (stixType === 'observed-data') {
            objectToAdd.number_observed = 1;
            objectToAdd.first_observed = baseObject.created;
            objectToAdd.last_observed = baseObject.modified;
          } else if (stixType === 'note') {
            objectToAdd.content = value;
            objectToAdd.description = attr.comment || 'MISP note';
          } else if (stixType === 'vulnerability') {
            objectToAdd.description = attr.comment || `Vulnerability ${value}`;
          } else if (stixType === 'malware') {
            objectToAdd.malware_types = category === 'Payload delivery' ? ['trojan'] : ['unknown'];
          } else if (stixType === 'threat-actor') {
            objectToAdd.threat_actor_types = ['unknown'];
          } else if (stixType === 'campaign') {
            objectToAdd.name = value;
          } else if (stixType === 'attack-pattern') {
            objectToAdd.description = attr.comment || `Attack Pattern ${value}`;
          } else if (stixType === 'course-of-action') {
            objectToAdd.description = attr.comment || `Course of Action ${value}`;
          } else if (stixType === 'identity') {
            objectToAdd.identity_class = category === 'Person' ? 'individual' : 'organization';
          } else if (stixType === 'infrastructure') {
            objectToAdd.infrastructure_types = ['unknown'];
          } else if (stixType === 'intrusion-set') {
            objectToAdd.description = attr.comment || `Intrusion Set ${value}`;
          } else if (stixType === 'location') {
            objectToAdd.name = value;
          } else if (stixType === 'tool') {
            objectToAdd.tool_types = ['unknown'];
          } else if (stixType === 'grouping') {
            objectToAdd.description = attr.comment || `Grouping ${value}`;
          } else if (stixType === 'malware-analysis') {
            objectToAdd.product = value;
          } else if (stixType === 'opinion') {
            objectToAdd.opinion = value;
          } else if (stixType === 'report') {
            objectToAdd.published = baseObject.created;
            objectToAdd.object_refs = [];
          }
        } else {
          switch (stixType) {
            case 'ipv4-addr':
            case 'ipv6-addr':
              const ipValue = compositeValues?.[0] || value;
              if (!isValidIp(ipValue)) {
                console.warn(`Invalid IP address for attribute ${attrUuid}: ${ipValue}`);
                objectToAdd = {
                  ...baseObject,
                  type: 'observed-data',
                  number_observed: 1,
                  first_observed: baseObject.created,
                  last_observed: baseObject.modified,
                  description: `Invalid IP address from MISP attribute: ${ipValue}`,
                };
              } else {
                objectToAdd = {
                  ...baseObject,
                  type: ipValue.includes(':') ? 'ipv6-addr' : 'ipv4-addr',
                  value: ipValue,
                };
              }
              break;
            case 'domain-name':
              const domainValue = compositeValues?.[0] || value;
              if (!isValidDomain(domainValue)) {
                console.warn(`Invalid domain: ${domainValue}`);
                continue;
              }
              const resolvesToRefs = compositeValues?.[1] && isValidIp(compositeValues[1])
                ? [generateStixId(compositeValues[1].includes(':') ? 'ipv6-addr' : 'ipv4-addr', compositeValues[1])]
                : undefined;
              objectToAdd = {
                ...baseObject,
                value: domainValue,
                resolves_to_refs: resolvesToRefs,
              };
              break;
            case 'url':
              if (!isValidUrl(value)) {
                console.warn(`Invalid URL: ${value}`);
                continue;
              }
              objectToAdd = {
                ...baseObject,
                value,
              };
              break;
            case 'email-addr':
              if (!isValidEmail(value)) {
                console.warn(`Invalid email: ${value}`);
                continue;
              }
              objectToAdd = {
                ...baseObject,
                value,
              };
              break;
            case 'file':
              const hashTypeMap: Record<string, string> = {
                md5: 'MD5',
                sha1: 'SHA-1',
                sha256: 'SHA-256',
                sha512: 'SHA-512',
                sha224: 'SHA-224',
                sha384: 'SHA-384',
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
              const hashType = hashTypeMap[attr.type.split('|')[0]] || 'SHA-256';
              const fileName = compositeValues?.[0] || (attr.type === 'filename' ? value : undefined);
              const hashes: Record<string, string> = {};
              if (compositeValues) {
                const hashKey = hashTypeMap[attr.type.split('|')[1]];
                if (hashKey) hashes[hashKey] = compositeValues[1];
              } else if (hashType) {
                hashes[hashType] = value;
              }
              objectToAdd = {
                ...baseObject,
                name: fileName,
                hashes,
              };
              break;
            case 'mutex':
              objectToAdd = { ...baseObject, name: value };
              break;
            case 'windows-registry-key':
              const [key, regValue] = compositeValues || [value, undefined];
              objectToAdd = {
                ...baseObject,
                key,
                values: regValue ? [{ name: regValue }] : undefined,
              };
              break;
            case 'x509-certificate':
              const x509HashType = attr.type.split('-')[2]?.toUpperCase();
              objectToAdd = {
                ...baseObject,
                hashes: x509HashType ? { [x509HashType]: value } : {},
              };
              break;
            case 'autonomous-system':
              objectToAdd = {
                ...baseObject,
                number: parseInt(value.replace('AS', ''), 10) || 0,
              };
              break;
            case 'network-traffic':
              const [ip, port] = compositeValues || [value, undefined];
              objectToAdd = {
                ...baseObject,
                dst_ref: ip && isValidIp(ip) ? generateStixId(ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr', ip) : undefined,
                dst_port: port ? parseInt(port, 10) : undefined,
              };
              break;
            case 'software':
              objectToAdd = { ...baseObject, name: value };
              break;
            case 'user-account':
              objectToAdd = {
                ...baseObject,
                user_id: value,
                account_type: category === 'Financial fraud' ? 'financial' : 'unknown',
              };
              break;
            case 'identity':
              objectToAdd = {
                ...baseObject,
                name: value,
                identity_class: category === 'Person' ? 'individual' : 'organization',
              };
              break;
            case 'location':
              objectToAdd = { ...baseObject, name: value };
              break;
            case 'infrastructure':
              objectToAdd = {
                ...baseObject,
                name: value,
                infrastructure_types: ['unknown'],
              };
              break;
            case 'artifact':
              objectToAdd = { ...baseObject, payload_bin: value };
              break;
            case 'mac-address':
              if (!isValidMacAddress(value)) {
                console.warn(`Invalid MAC address: ${value}`);
                continue;
              }
              objectToAdd = {
                ...baseObject,
                value,
              };
              break;
            case 'process':
              objectToAdd = { ...baseObject, command_line: value };
              break;
            case 'directory':
              objectToAdd = { ...baseObject, path: value };
              break;
            default:
              console.warn(`Unhandled STIX type ${stixType} for attribute ${attrUuid}`);
              objectToAdd = {
                ...baseObject,
                type: 'observed-data',
                number_observed: 1,
                first_observed: baseObject.created,
                last_observed: baseObject.modified,
                description: `Fallback for unhandled type ${attr.type}: ${value}`,
              };
          }
        }

        if (objectToAdd) {
          yield tlpMarking;
          yield objectToAdd;
          stixObjectMap[attrUuid] = objectToAdd;
          if (report) report.object_refs.push(objectToAdd.id);

          if (toIds && STIX_SCO_TYPES.includes(stixType)) {
            const indicatorObj: GenericStixObject = {
              ...baseObject,
              id: generateStixId('indicator', attrUuid),
              type: 'indicator',
              pattern: objectToAdd.pattern || `[${stixType}:value = '${value.replace(/'/g, "\\'")}']`,
              name:objectToAdd.value,
              pattern_type: 'stix',
              valid_from: baseObject.created,
              object_marking_refs: [tlpMarking.id],
            };
            const relationship = createRelationship(
              indicatorObj.id,
              objectToAdd.id,
              'based-on',
              timestamp,
              `Indicator based on SCO: ${stixType}`,
              baseObject.created,
              undefined
            );
            yield indicatorObj;
            yield relationship;
            stixObjectMap[`indicator-${attrUuid}`] = indicatorObj;
            createdRelationships.add(relationship.id);
            if (report) report.object_refs.push(indicatorObj.id, relationship.id);
          }
        }
      } catch (error) {
        console.error(`Error processing MISP attribute ${attr.uuid || 'unknown'}: ${(error as Error).message}`);
      }
    }

    // Process MISP Objects
    for (const obj of objects) {
      try {
        for (const stixObj of processMispObject(obj, eventTimestamp)) {
          yield stixObj;
          stixObjectMap[obj.uuid || stixObj.id] = stixObj;
          if (report) report.object_refs.push(stixObj.id);
        }
      } catch (error) {
        console.error(`Error processing MISP object ${obj.uuid || 'unknown'}: ${(error as Error).message}`);
      }
    }

    // Process Explicit MISP Object References
    for (const ref of objectReferences) {
      const sourceUuid = ref.object_uuid;
      const targetUuid = ref.referenced_uuid;
      const sourceObj = stixObjectMap[sourceUuid];
      const targetObj = stixObjectMap[targetUuid];
      let relationshipType = ref.relationship_type || 'related-to';

      if (sourceObj && targetObj) {
        const mappedType = mapMispRelationshipToStix(relationshipType, sourceObj.type, targetObj.type);
        relationshipType = mappedType && validRelationships.get(sourceObj.type)?.has(mappedType) &&
                          validTargets.get(mappedType)?.has(targetObj.type) ? mappedType : 'related-to';

        const relationshipId = generateStixId('relationship', `${sourceObj.id}_${relationshipType}_${targetObj.id}`);
        if (!createdRelationships.has(relationshipId)) {
          const relationship = createRelationship(
            sourceObj.id,
            targetObj.id,
            relationshipType,
            eventTimestamp,
            `MISP Object Reference: ${relationshipType}`,
            moment(eventTimestamp * 1000).toISOString(),
            undefined
          );
          yield relationship;
          createdRelationships.add(relationshipId);
          if (report) report.object_refs.push(relationship.id);
        }
      }
    }

    const processedPairs = new Set<string>();
for (const sourceObj of Object.values(stixObjectMap)) {
  const allowedRelationshipTypes = validRelationships.get(sourceObj.type) || new Set();
  if (allowedRelationshipTypes.size === 0) continue;

  for (const targetObj of Object.values(stixObjectMap)) {
    if (sourceObj.id === targetObj.id || STIX_RELATIONSHIP_TYPES.includes(targetObj.type)) continue;

    for (const relType of allowedRelationshipTypes) {
      const allowedTargetsForRel = validTargets.get(relType) || new Set();
      if (!allowedTargetsForRel.has(targetObj.type)) continue;

      const pairKey = `${sourceObj.id}_${targetObj.id}_${relType}`;
      if (processedPairs.has(pairKey)) continue;

      let inferredType: string | null = null;
      if (sourceObj.type === 'malware' && targetObj.type === 'file' && sourceObj.labels?.includes('dropper')) {
        inferredType = 'drops';
      } else if (sourceObj.type === 'malware' && targetObj.type === 'file' && targetObj.labels?.includes('delivered')) {
        inferredType = 'delivers';
      } else if (sourceObj.type === 'threat-actor' && targetObj.type === 'campaign') {
        inferredType = 'attributed-to';
      } else if (sourceObj.type === 'indicator' && relType === 'indicates') {
        // Explicitly validate that target is a valid SDO for 'indicates'
        const validIndicatesTargets = new Set(['attack-pattern', 'campaign', 'infrastructure', 'intrusion-set', 'malware', 'threat-actor', 'tool']);
        if (validIndicatesTargets.has(targetObj.type)) {
          inferredType = 'indicates';
        } else {
          console.warn(`Skipping invalid 'indicates' relationship from indicator to ${targetObj.type}: ${sourceObj.id} -> ${targetObj.id}`);
          continue;
        }
      }

      if (inferredType) {
        const relationshipId = generateStixId('relationship', `${sourceObj.id}_${inferredType}_${targetObj.id}`);
        if (!createdRelationships.has(relationshipId)) {
          const relationship = createRelationship(
            sourceObj.id,
            targetObj.id,
            inferredType,
            eventTimestamp,
            `Inferred: ${sourceObj.type} ${inferredType} ${targetObj.type}`,
            moment(eventTimestamp * 1000).toISOString(),
            undefined
          );
          console.log(`Creating inferred relationship: ${sourceObj.type} (${sourceObj.id}) ${inferredType} ${targetObj.type} (${targetObj.id})`);
          yield relationship;
          createdRelationships.add(relationshipId);
          if (report) report.object_refs.push(relationship.id);
          processedPairs.add(pairKey);
        }
      }
    }
  }
}

    // Process Domain-IP Relationships
    for (const obj of Object.values(stixObjectMap)) {
      if (obj.type === 'domain-name' && obj.resolves_to_refs) {
        for (const ref of obj.resolves_to_refs) {
          const ipObj = stixObjectMap[ref.split('--')[1]]; // Extract UUID from ID
          if (ipObj) {
            const relationshipId = generateStixId('relationship', `${obj.id}_resolves-to_${ipObj.id}`);
            if (!createdRelationships.has(relationshipId)) {
              const relationship = createRelationship(
                obj.id,
                ipObj.id,
                'resolves-to',
                eventTimestamp,
                'Domain resolves to IP address',
                moment(eventTimestamp * 1000).toISOString(),
                undefined
              );
              yield relationship;
              createdRelationships.add(relationshipId);
              if (report) report.object_refs.push(relationship.id);
            }
          }
        }
      }
    }

    // Process Sightings
    for (const sighting of (event.Sighting || [])) {
      const sightedObject = stixObjectMap[sighting.attribute_uuid];
      if (sightedObject) {
        const orgIdentity: GenericStixObject =
          Object.values(stixObjectMap).find((o) => o.type === 'identity' && o.identity_class === 'organization') ||
          {
            id: generateStixId('identity', 'misp-org'),
            type: 'identity',
            spec_version: STIX_VERSION,
            identity_class: 'organization',
            name: 'MISP Organization',
            created: moment(eventTimestamp * 1000).toISOString(),
            modified: moment(eventTimestamp * 1000).toISOString(),
            object_marking_refs: [createTLPMarking('white', eventTimestamp).id],
          };

        const sightingTimestamp = sighting.date_sighting || eventTimestamp;
        const tlpMarking = createTLPMarking('white', sightingTimestamp);
        const sightingObj = createSighting(
          sightedObject.id,
          [orgIdentity.id],
          sightingTimestamp,
          sighting.count ? parseInt(sighting.count, 10) : undefined,
          sighting.comment || `Sighting of ${sightedObject.type} from MISP`,
          undefined,
          sighting.type === '0' ? true : false
        );

        if (!stixObjectMap['misp-org']) {
          yield tlpMarking;
          yield orgIdentity;
          stixObjectMap['misp-org'] = orgIdentity;
          if (report) report.object_refs.push(orgIdentity.id);
        }
        yield tlpMarking;
        yield sightingObj;
        if (report) report.object_refs.push(sightingObj.id);
      }
    }

    // Yield the report last to ensure all object_refs are populated
    if (report) {
      yield report;
    }

    console.log(`Processed MISP data, yielding STIX objects incrementally`);
  } catch (error) {
    console.error(`MISP processing error: ${(error as Error).message}`, {
      raw: JSON.stringify(raw, null, 2).substring(0, 500),
    });
  }
}

function* processAlienVaultOTXPulse(raw: any): Generator<GenericStixObject, void, unknown> {
  try {
    console.log(`[alienVaultOTX] Starting processing of AlienVault OTX pulse data: ${JSON.stringify(raw, null, 2).substring(0, 1000)}`);
    if (!raw || typeof raw !== 'object' || !raw.indicators || !Array.isArray(raw.indicators)) {
      console.warn(`[alienVaultOTX] Invalid AlienVault OTX pulse data: ${JSON.stringify(raw, null, 2).substring(0, 500)}`);
      return;
    }

    const stixObjectMap: Record<string, GenericStixObject> = {};
    const pulseId = raw.id || raw.pulse_id || uuidv5('alienvault-otx-pulse', NAMESPACE);
    const pulseName = raw.name || 'AlienVault OTX Pulse';
    const pulseDescription = raw.description || pulseName;
    const tags = Array.isArray(raw.tags) ? raw.tags.map((tag: string) => tag.toLowerCase()) : [];
    const timestamp = raw.created ? moment(raw.created).unix() : Math.floor(Date.now() / 1000);
    const created = moment(timestamp * 1000).toISOString();
    const modified = raw.modified ? moment(raw.modified).toISOString() : created;
    const adversary = raw.adversary || '';
    const industries = Array.isArray(raw.industries) ? raw.industries.map((ind: string) => ind.toLowerCase()) : [];
    const attackIds = Array.isArray(raw.attack_ids) ? raw.attack_ids : [];
    const tlp = (raw.tlp || 'white') as 'white' | 'green' | 'amber' | 'red';

    // Calculate confidence 
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

    // External references (unchanged)
    const externalReferences = raw.references && Array.isArray(raw.references)
      ? raw.references.map((ref: string, index: number) => ({
          source_name: 'AlienVault OTX Reference',
          external_id: `ref-${index}`,
          url: ref,
          description: 'Reference from OTX pulse',
        }))
      : [];
    if (pulseId) {
      externalReferences.unshift({
        source_name: 'AlienVault OTX',
        external_id: pulseId,
        url: `https://otx.alienvault.com/pulse/${pulseId}`,
        description: 'OTX pulse',
      });
    }

    // Create TLP marking
    const tlpMarking = createTLPMarking(tlp, timestamp);
    console.log(`[alienVaultOTX] Created TLP marking for pulse ${pulseId}: TLP ${tlp}, ID ${tlpMarking.id}`);
    yield tlpMarking;
    stixObjectMap[tlpMarking.id] = tlpMarking;

    // Create STIX report
    const report: GenericStixObject = {
      id: generateStixId('report', pulseId),
      type: 'report',
      spec_version: STIX_VERSION,
      name: pulseName,
      description: pulseDescription,
      published: created,
      object_refs: [],
      labels: ['alienvault-otx', 'osint', ...tags, ...(adversary ? [`adversary:${adversary}`] : [])],
      created,
      modified,
      confidence,
      external_references: externalReferences.length > 0 ? externalReferences : undefined,
      object_marking_refs: [tlpMarking.id],
    };
    console.log(`[alienVaultOTX] Created STIX report for pulse ${pulseId}: ${report.id}, ${report.name}`);
    yield report;
    stixObjectMap[report.id] = report;

    let processedIndicators = 0;
    let skippedIndicators = 0;

    // Process indicators
    for (const indicator of raw.indicators) {
      try {
        console.log(`[alienVaultOTX] Processing indicator for pulse ${pulseId}: ${JSON.stringify(indicator, null, 2).substring(0, 500)}`);
        if (!indicator.type || !indicator.indicator || indicator.is_active !== 1) {
          console.warn(`[alienVaultOTX] Skipping invalid or inactive indicator for pulse ${pulseId}: ${JSON.stringify(indicator, null, 2).substring(0, 500)}`);
          skippedIndicators++;
          continue;
        }

        const typeMap: Record<string, StixType> = {
          IPv4: 'ipv4-addr',
          IPv6: 'ipv6-addr',
          domain: 'domain-name',
          hostname: 'domain-name',
          URL: 'url',
          'FileHash-MD5': 'file',
          'FileHash-SHA1': 'file',
          'FileHash-SHA256': 'file',
          CVE: 'vulnerability',
          YARA: 'indicator',
          email: 'email-addr',
        };

        const hashTypes: Record<string, string> = {
          'FileHash-MD5': 'MD5',
          'FileHash-SHA1': 'SHA-1',
          'FileHash-SHA256': 'SHA-256',
        };

        const stixType = typeMap[indicator.type] || 'observed-data';
        const value = indicator.indicator;
        const indicatorId = indicator.id || `${pulseId}_${value}`;
        const indicatorDescription = indicator.description || pulseDescription;

        const baseObj: GenericStixObject = {
          id: generateStixId(stixType, value || indicatorId),
          type: stixType,
          spec_version: STIX_VERSION,
          created: indicator.created ? moment(indicator.created).toISOString() : created,
          modified,
          labels: [
            'alienvault-otx',
            'osint',
            ...tags,
            ...(adversary ? [`adversary:${adversary}`] : []),
            ...(industries.map((ind: string) => `industry:${ind}`)),
          ],
          description: indicatorDescription,
          confidence,
          external_references: externalReferences.length > 0 ? externalReferences : undefined,
          sourceConfigId: 'alienvault-otx-feed',
          object_marking_refs: [tlpMarking.id],
        };

        let stixObj: GenericStixObject | null = null;
        switch (stixType) {
          case 'ipv4-addr':
          case 'ipv6-addr':
            if (!value.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/)) {
              console.warn(`[alienVaultOTX] Invalid IP address for pulse ${pulseId}, indicator ${indicatorId}: ${value}`);
              skippedIndicators++;
              continue;
            }
            stixObj = {
              ...baseObj,
              value,
              indicator: value,
              pattern: `[${stixType}:value = '${value.replace(/'/g, "\\'")}']`,
              pattern_type: 'stix',
            };
            break;
          case 'domain-name':
            if (!value.match(/^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/)) {
              console.warn(`[alienVaultOTX] Invalid domain name for pulse ${pulseId}, indicator ${indicatorId}: ${value}`);
              skippedIndicators++;
              continue;
            }
            stixObj = {
              ...baseObj,
              value,
              indicator: value,
              pattern: `[domain-name:value = '${value.replace(/'/g, "\\'")}']`,
              pattern_type: 'stix',
            };
            break;
          case 'url':
            try {
              new URL(value);
              stixObj = {
                ...baseObj,
                value,
                indicator: value,
                pattern: `[url:value = '${value.replace(/'/g, "\\'")}']`,
                pattern_type: 'stix',
              };
            } catch {
              console.warn(`[alienVaultOTX] Invalid URL for pulse ${pulseId}, indicator ${indicatorId}: ${value}`);
              skippedIndicators++;
              continue;
            }
            break;
          case 'email-addr':
            if (!value.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
              console.warn(`[alienVaultOTX] Invalid email address for pulse ${pulseId}, indicator ${indicatorId}: ${value}`);
              skippedIndicators++;
              continue;
            }
            stixObj = {
              ...baseObj,
              value,
              indicator: value,
              pattern: `[email-addr:value = '${value.replace(/'/g, "\\'")}']`,
              pattern_type: 'stix',
            };
            break;
          case 'file':
            const hashType = hashTypes[indicator.type];
            if (!value.match(/^[0-9a-fA-F]+$/)) {
              console.warn(`[alienVaultOTX] Invalid hash value for pulse ${pulseId}, indicator ${indicatorId}: ${value}`);
              skippedIndicators++;
              continue;
            }
            stixObj = {
              ...baseObj,
              hashes: {
                MD5: hashType === 'MD5' ? value : undefined,
                'SHA-1': hashType === 'SHA-1' ? value : undefined,
                'SHA-256': hashType === 'SHA-256' ? value : undefined,
                'SHA-512': undefined,
              },
              indicator: value,
              pattern: `[file:hashes.'${hashType}' = '${value}']`,
              pattern_type: 'stix',
            };
            break;
          case 'vulnerability':
            if (!value.startsWith('CVE-')) {
              console.warn(`[alienVaultOTX] Invalid CVE identifier for pulse ${pulseId}, indicator ${indicatorId}: ${value}`);
              skippedIndicators++;
              continue;
            }
            stixObj = {
              ...baseObj,
              name: value,
              description: indicatorDescription,
            };
            break;
          case 'indicator':
            stixObj = {
              ...baseObj,
              pattern: `[${indicator.type.toLowerCase()}:value = '${value.replace(/'/g, "\\'")}']`,
              pattern_type: 'stix',
              valid_from: created,
              indicator: value,
            };
            break;
          default:
            stixObj = {
              ...baseObj,
              type: 'observed-data',
              number_observed: 1,
              first_observed: created,
              last_observed: modified,
              description: `Fallback for unsupported indicator type ${indicator.type}: ${value}`,
            };
            console.log(`[alienVaultOTX] Created fallback observed-data for pulse ${pulseId}, indicator ${indicatorId}: ${stixObj.id}`);
            break;
        }

        if (stixObj) {
          console.log(`[alienVaultOTX] Created STIX object for pulse ${pulseId}, indicator ${indicatorId}: ${stixType} (${stixObj.id})`);
          yield stixObj;
          stixObjectMap[stixObj.id] = stixObj;
          report.object_refs = [...(report.object_refs || []), stixObj.id];
          processedIndicators++;
        }
      } catch (error) {
        console.error(`[alienVaultOTX] Error processing indicator ${indicator.id || 'unknown'} for pulse ${pulseId}: ${(error as Error).message}`, {
          indicator: JSON.stringify(indicator, null, 2).substring(0, 500),
        });
        skippedIndicators++;
      }
    }

    console.log(`[alienVaultOTX] Completed processing pulse ${pulseId}: ${processedIndicators} indicators processed, ${skippedIndicators} skipped, ${Object.keys(stixObjectMap).length} STIX objects created`);
  } catch (error) {
    console.error(`[alienVaultOTX] Error processing AlienVault OTX pulse ${this.pulseId}: ${(error as Error).message}`, {
      raw: JSON.stringify(raw, null, 2).substring(0, 500),
    });
  }
}




function* processHybridAnalysis(raw: any): Generator<GenericStixObject, void, unknown> {

  const isValidMd5 = (hash: string): boolean => {
    return /^[0-9a-fA-F]{32}$/.test(hash);
  };
  
  const isValidSha1 = (hash: string): boolean => {
    return /^[0-9a-fA-F]{40}$/.test(hash);
  };
  
  const isValidSha256 = (hash: string): boolean => {
    return /^[0-9a-fA-F]{64}$/.test(hash);
  };
  
  // Valid Relationships and Targets (from MISP mapper)
  const validRelationships = new Map<string, Set<string>>([
    ['attack-pattern', new Set(['delivers', 'targets', 'uses'])],
    ['campaign', new Set(['attributed-to', 'compromises', 'originates-from', 'targets', 'uses'])],
    ['course-of-action', new Set(['investigates', 'mitigates'])],
    ['identity', new Set(['located-at'])],
    ['indicator', new Set(['indicates', 'based-on'])],
    ['infrastructure', new Set(['communicates-with', 'consists-of', 'controls', 'delivers', 'has', 'hosts', 'located-at', 'uses'])],
    ['intrusion-set', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'originates-from', 'targets', 'uses'])],
    ['malware', new Set(['authored-by', 'beacons-to', 'exfiltrate-to', 'communicates-with', 'controls', 'downloads', 'drops', 'exploits', 'originates-from', 'targets', 'uses', 'variant-of'])],
    ['malware-analysis', new Set(['characterizes', 'analysis-of', 'static-analysis-of', 'dynamic-analysis-of'])],
    ['threat-actor', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'impersonates', 'located-at', 'targets', 'uses'])],
    ['tool', new Set(['delivers', 'drops', 'has', 'targets'])],
  ]);
  
  const validTargets = new Map<string, Set<string>>([
    ['delivers', new Set(['malware'])],
    ['targets', new Set(['identity', 'location', 'vulnerability', 'infrastructure'])],
    ['uses', new Set(['attack-pattern', 'infrastructure', 'malware', 'tool'])],
    ['attributed-to', new Set(['intrusion-set', 'threat-actor', 'identity'])],
    ['compromises', new Set(['infrastructure'])],
    ['originates-from', new Set(['location'])],
    ['investigates', new Set(['indicator'])],
    ['mitigates', new Set(['attack-pattern', 'indicator', 'malware', 'tool', 'vulnerability'])],
    ['located-at', new Set(['location'])],
    ['indicates', new Set(['attack-pattern', 'campaign', 'infrastructure', 'intrusion-set', 'malware', 'threat-actor', 'tool'])],
    ['based-on', new Set(['observed-data'])],
  ]);


  try {
    console.log(`Processing Hybrid Analysis data: ${JSON.stringify(raw, null, 2).substring(0, 1000)}`);
    if (!raw || typeof raw !== 'object') {
      console.warn(`Invalid Hybrid Analysis data: ${JSON.stringify(raw, null, 2).substring(0, 500)}`);
      return;
    }

    const stixObjectMap: Record<string, GenericStixObject> = {};
    const createdRelationships: Set<string> = new Set();
    const timestamp = raw.analysis_start_time ? moment(raw.analysis_start_time).unix() : moment().unix();
    const created = moment(timestamp * 1000).toISOString();
    const modified = created;
    const jobId = raw.job_id || uuidv5('hybrid-analysis-sample', NAMESPACE);
    const verdict = raw.threat_level_human || 'unknown';
    const threatScore = raw.threat_score || 0;
    const avDetect = raw.av_detect || 0;
    const fileType = raw.type || 'unknown';
    const submitName = raw.submit_name || '';
    const isUrlAnalysis = raw.url_analysis || false;
    const environment = raw.environment_description || 'unknown';
    const processes = Array.isArray(raw.processes) ? raw.processes : [];
    const domains = Array.isArray(raw.domains) ? raw.domains : [];
    const hosts = Array.isArray(raw.hosts) ? raw.hosts : [];
    const extractedFiles = Array.isArray(raw.extracted_files) ? raw.extracted_files : [];
    const geolocation = Array.isArray(raw.hosts_geolocation) ? raw.hosts_geolocation : [];
    const reportUrl = raw.report_url ? `https://www.hybrid-analysis.com${raw.report_url}` : null;
    const tags = Array.isArray(raw.tags) ? raw.tags.map((tag: string) => tag.toLowerCase()) : [];
    const tlp = (raw.tlp || 'white') as 'white' | 'green' | 'amber' | 'red';

    // Calculate confidence (unchanged)
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

    // Description (unchanged)
    const description = [
      `Hybrid Analysis sample: ${fileType}`,
      `Verdict: ${verdict}`,
      `Threat Score: ${threatScore}`,
      `Environment: ${environment}`,
      processes.length > 0 ? `Processes: ${processes.map((p: any) => p.name).join(', ')}` : null,
      tags.length > 0 ? `Tags: ${tags.join(', ')}` : null,
    ].filter(Boolean).join('; ');

    // External references (unchanged)
    const externalReferences = [];
    if (raw.sha256 || raw.md5 || jobId) {
      externalReferences.push({
        source_name: 'Hybrid Analysis',
        external_id: raw.sha256 || raw.md5 || jobId,
        url: reportUrl || `https://www.hybrid-analysis.com/sample/${raw.sha256 || raw.md5 || jobId}`,
        description: 'Hybrid Analysis sample',
      });
    }

    // Create TLP marking
    const tlpMarking = createTLPMarking(tlp, timestamp);
    yield tlpMarking;

    // Create STIX report
    const report: GenericStixObject = {
      id: generateStixId('report', jobId),
      type: 'report',
      spec_version: STIX_VERSION,
      name: `Hybrid Analysis Report: ${fileType}`,
      description,
      published: created,
      object_refs: [],
      labels: ['hybrid-analysis', `verdict:${verdict.toLowerCase()}`, ...tags.map((tag: string) => `tag:${tag}`)],
      created,
      modified,
      confidence,
      external_references: externalReferences.length > 0 ? externalReferences : undefined,
      object_marking_refs: [tlpMarking.id],
    };
    stixObjectMap[jobId] = report;

    // Base object for SCOs
    const baseObj: GenericStixObject = {
      id: generateStixId('file', raw.sha256 || raw.md5 || jobId),
      type: 'file',
      spec_version: STIX_VERSION,
      created,
      modified,
      labels: [
        'hybrid-analysis',
        `verdict:${verdict.toLowerCase()}`,
        ...Array.from(
          new Set(
            geolocation
              .filter((geo: any) => geo.country && typeof geo.country === 'string')
              .map((geo: any) => `geolocation:${geo.country.toLowerCase()}`)
          )
        ),
        ...tags.map((tag: string) => `tag:${tag}`),
      ],
      description,
      confidence,
      external_references: externalReferences.length > 0 ? externalReferences : undefined,
      sourceConfigId: 'hybrid-analysis-feed',
      object_marking_refs: [tlpMarking.id],
    };

    // Yield file object if hashes exist
    let primaryFileObj: GenericStixObject | null = null;
    if (raw.sha256 || raw.md5 || raw.sha1) {
      const hashes: Record<string, string | undefined> = {
        MD5: isValidMd5(raw.md5) ? raw.md5 : undefined,
        'SHA-1': isValidSha1(raw.sha1) ? raw.sha1 : undefined,
        'SHA-256': isValidSha256(raw.sha256) ? raw.sha256 : undefined,
        'SHA-512': undefined,
      };
      if (hashes.MD5 || hashes['SHA-1'] || hashes['SHA-256']) {
        primaryFileObj = {
          ...baseObj,
          name: submitName || undefined,
          hashes,
          pattern: hashes['SHA-256'] ? `[file:hashes.'SHA-256' = '${hashes['SHA-256']}']` : undefined,
          pattern_type: 'stix',
        };
        yield primaryFileObj;
        stixObjectMap[baseObj.id] = primaryFileObj;
        report.object_refs.push(primaryFileObj.id);

        // Create indicator for file
        const indicatorObj: GenericStixObject = {
          ...baseObj,
          id: generateStixId('indicator', `indicator-${baseObj.id}`),
          type: 'indicator',
          pattern: primaryFileObj.pattern || `[file:hashes.'SHA-256' = '${hashes['SHA-256'] || 'unknown'}']`,
          pattern_type: 'stix',
          valid_from: created,
          description: `Indicator for file: ${hashes['SHA-256'] || hashes['SHA-1'] || hashes.MD5}`,
        };
        const relationship = createRelationship(
          indicatorObj.id,
          primaryFileObj.id,
          'based-on',
          timestamp,
          'Indicator based on file',
          created
        );
        yield indicatorObj;
        yield relationship;
        stixObjectMap[`indicator-${baseObj.id}`] = indicatorObj;
        createdRelationships.add(relationship.id);
        report.object_refs.push(indicatorObj.id, relationship.id);
      }
    }

    // Handle URL analysis
    if (isUrlAnalysis && submitName && isValidUrl(submitName)) {
      const urlObj: GenericStixObject = {
        ...baseObj,
        id: generateStixId('url', submitName),
        type: 'url',
        value: submitName,
        pattern: `[url:value = '${submitName.replace(/'/g, "\\'")}']`,
        pattern_type: 'stix',
      };
      yield urlObj;
      stixObjectMap[submitName] = urlObj;
      report.object_refs.push(urlObj.id);

      // Create relationship: file → url
      if (primaryFileObj && validRelationships.get('file')?.has('downloaded-from')) {
        const relationship = createRelationship(
          primaryFileObj.id,
          urlObj.id,
          'downloaded-from',
          timestamp,
          'File downloaded from URL',
          created
        );
        yield relationship;
        createdRelationships.add(relationship.id);
        report.object_refs.push(relationship.id);
      }

      // Create indicator for URL
      const indicatorObj: GenericStixObject = {
        ...baseObj,
        id: generateStixId('indicator', `indicator-${urlObj.id}`),
        type: 'indicator',
        pattern: urlObj.pattern,
        pattern_type: 'stix',
        valid_from: created,
        description: `Indicator for URL: ${submitName}`,
      };
      const relationship = createRelationship(
        indicatorObj.id,
        urlObj.id,
        'based-on',
        timestamp,
        'Indicator based on URL',
        created
      );
      yield indicatorObj;
      yield relationship;
      stixObjectMap[`indicator-${urlObj.id}`] = indicatorObj;
      createdRelationships.add(relationship.id);
      report.object_refs.push(indicatorObj.id, relationship.id);
    } else if (isUrlAnalysis && submitName) {
      console.warn(`Invalid URL value: ${submitName}`);
      const observedObj: GenericStixObject = {
        ...baseObj,
        id: generateStixId('observed-data', `url-${jobId}`),
        type: 'observed-data',
        number_observed: 1,
        first_observed: created,
        last_observed: modified,
        description: `Invalid URL from Hybrid Analysis: ${submitName}`,
      };
      yield observedObj;
      stixObjectMap[`url-${jobId}`] = observedObj;
      report.object_refs.push(observedObj.id);
    }

    // Process domains
    for (const domain of domains) {
      try {
        if (isValidDomain(domain)) {
          const domainObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('domain-name', domain),
            type: 'domain-name',
            value: domain,
            pattern: `[domain-name:value = '${domain.replace(/'/g, "\\'")}']`,
            pattern_type: 'stix',
          };
          yield domainObj;
          stixObjectMap[domain] = domainObj;
          report.object_refs.push(domainObj.id);

          // Create relationship: domain → file
          if (primaryFileObj && validRelationships.get('domain-name')?.has('communicates-with')) {
            const relationship = createRelationship(
              domainObj.id,
              primaryFileObj.id,
              'communicates-with',
              timestamp,
              'Domain communicates with file',
              created
            );
            yield relationship;
            createdRelationships.add(relationship.id);
            report.object_refs.push(relationship.id);
          }

          // Create indicator for domain
          const indicatorObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('indicator', `indicator-${domainObj.id}`),
            type: 'indicator',
            pattern: domainObj.pattern,
            pattern_type: 'stix',
            valid_from: created,
            description: `Indicator for domain: ${domain}`,
          };
          const relationship = createRelationship(
            indicatorObj.id,
            domainObj.id,
            'based-on',
            timestamp,
            'Indicator based on domain',
            created
          );
          yield indicatorObj;
          yield relationship;
          stixObjectMap[`indicator-${domainObj.id}`] = indicatorObj;
          createdRelationships.add(relationship.id);
          report.object_refs.push(indicatorObj.id, relationship.id);
        } else {
          console.warn(`Invalid domain: ${domain}`);
          const observedObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('observed-data', `domain-${domain}`),
            type: 'observed-data',
            number_observed: 1,
            first_observed: created,
            last_observed: modified,
            description: `Invalid domain from Hybrid Analysis: ${domain}`,
          };
          yield observedObj;
          stixObjectMap[`domain-${domain}`] = observedObj;
          report.object_refs.push(observedObj.id);
        }
      } catch (error) {
        console.error(`Error processing domain ${domain}: ${(error as Error).message}`);
      }
    }

    // Process unique IPs
    const uniqueIps = new Set<string>([
      ...hosts,
      ...(Array.isArray(raw.et_alerts) ? raw.et_alerts.map((alert: any) => alert.destination_ip).filter(Boolean) : []),
    ]);

    for (const ip of uniqueIps) {
      try {
        if (isValidIp(ip)) {
          const ipObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId(ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr', ip),
            type: ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr',
            value: ip,
            pattern: `[${ip.includes(':') ? 'ipv6-addr' : 'ipv4-addr'}:value = '${ip.replace(/'/g, "\\'")}']`,
            pattern_type: 'stix',
          };
          yield ipObj;
          stixObjectMap[ip] = ipObj;
          report.object_refs.push(ipObj.id);

          // Create relationships: domain → IP
          for (const domain of domains) {
            if (isValidDomain(domain) && validRelationships.get('domain-name')?.has('resolves-to')) {
              const relationship = createRelationship(
                generateStixId('domain-name', domain),
                ipObj.id,
                'resolves-to',
                timestamp,
                'Domain resolves to IP',
                created
              );
              yield relationship;
              createdRelationships.add(relationship.id);
              report.object_refs.push(relationship.id);
            }
          }

          // Create relationship: IP → file
          if (primaryFileObj && validRelationships.get(ipObj.type)?.has('communicates-with')) {
            const relationship = createRelationship(
              ipObj.id,
              primaryFileObj.id,
              'communicates-with',
              timestamp,
              'IP communicates with file',
              created
            );
            yield relationship;
            createdRelationships.add(relationship.id);
            report.object_refs.push(relationship.id);
          }

          // Create indicator for IP
          const indicatorObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('indicator', `indicator-${ipObj.id}`),
            type: 'indicator',
            pattern: ipObj.pattern,
            pattern_type: 'stix',
            valid_from: created,
            description: `Indicator for IP: ${ip}`,
          };
          const relationship = createRelationship(
            indicatorObj.id,
            ipObj.id,
            'based-on',
            timestamp,
            'Indicator based on IP',
            created
          );
          yield indicatorObj;
          yield relationship;
          stixObjectMap[`indicator-${ipObj.id}`] = indicatorObj;
          createdRelationships.add(relationship.id);
          report.object_refs.push(indicatorObj.id, relationship.id);
        } else {
          console.warn(`Invalid IP address: ${ip}`);
          const observedObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('observed-data', `ip-${ip}`),
            type: 'observed-data',
            number_observed: 1,
            first_observed: created,
            last_observed: modified,
            description: `Invalid IP address from Hybrid Analysis: ${ip}`,
          };
          yield observedObj;
          stixObjectMap[`ip-${ip}`] = observedObj;
          report.object_refs.push(observedObj.id);
        }
      } catch (error) {
        console.error(`Error processing IP ${ip}: ${(error as Error).message}`);
      }
    }

    // Process extracted files
    for (const file of extractedFiles) {
      try {
        const extractedHashes: Record<string, string | undefined> = {
          MD5: isValidMd5(file.md5) ? file.md5 : undefined,
          'SHA-1': isValidSha1(file.sha1) ? file.sha1 : undefined,
          'SHA-256': isValidSha256(file.sha256) ? file.sha256 : undefined,
          'SHA-512': undefined,
        };
        if (extractedHashes.MD5 || extractedHashes['SHA-1'] || extractedHashes['SHA-256']) {
          const extractedFileObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('file', file.sha256 || file.md5 || uuidv5(file.name || 'unknown', NAMESPACE)),
            type: 'file',
            hashes: extractedHashes,
            name: file.name || undefined,
            description: file.description || `Extracted file: ${file.name || 'unknown'}`,
            labels: [
              ...baseObj.labels,
              `type:${file.type_tags?.join(',') || 'unknown'}`,
            ],
            pattern: extractedHashes['SHA-256'] ? `[file:hashes.'SHA-256' = '${extractedHashes['SHA-256']}']` : undefined,
            pattern_type: 'stix',
          };
          yield extractedFileObj;
          stixObjectMap[extractedFileObj.id] = extractedFileObj;
          report.object_refs.push(extractedFileObj.id);

          // Create relationship: extracted file → parent file
          if (primaryFileObj && validRelationships.get('file')?.has('derived-from')) {
            const relationship = createRelationship(
              extractedFileObj.id,
              primaryFileObj.id,
              'derived-from',
              timestamp,
              'Extracted file derived from parent file',
              created
            );
            yield relationship;
            createdRelationships.add(relationship.id);
            report.object_refs.push(relationship.id);
          }

          // Create indicator for extracted file
          const indicatorObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('indicator', `indicator-${extractedFileObj.id}`),
            type: 'indicator',
            pattern: extractedFileObj.pattern || `[file:hashes.'SHA-256' = '${extractedHashes['SHA-256'] || 'unknown'}']`,
            pattern_type: 'stix',
            valid_from: created,
            description: `Indicator for extracted file: ${extractedHashes['SHA-256'] || extractedHashes['SHA-1'] || extractedHashes.MD5}`,
          };
          const relationship = createRelationship(
            indicatorObj.id,
            extractedFileObj.id,
            'based-on',
            timestamp,
            'Indicator based on extracted file',
            created
          );
          yield indicatorObj;
          yield relationship;
          stixObjectMap[`indicator-${extractedFileObj.id}`] = indicatorObj;
          createdRelationships.add(relationship.id);
          report.object_refs.push(indicatorObj.id, relationship.id);
        }
      } catch (error) {
        console.error(`Error processing extracted file ${file.name || 'unknown'}: ${(error as Error).message}`);
      }
    }

    // Process processes
    for (const process of processes) {
      try {
        if (process.sha256 && isValidSha256(process.sha256)) {
          const processFileObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('file', process.sha256),
            type: 'file',
            hashes: {
              'SHA-256': process.sha256,
              MD5: undefined,
              'SHA-1': undefined,
              'SHA-512': undefined,
            },
            description: `Process: ${process.name || 'unknown'}; Path: ${process.normalized_path || 'unknown'}`,
            labels: [...baseObj.labels, 'process'],
            pattern: `[file:hashes.'SHA-256' = '${process.sha256}']`,
            pattern_type: 'stix',
          };
          yield processFileObj;
          stixObjectMap[process.sha256] = processFileObj;
          report.object_refs.push(processFileObj.id);

          // Create relationship: process file → parent file
          if (primaryFileObj && validRelationships.get('file')?.has('executed-by')) {
            const relationship = createRelationship(
              processFileObj.id,
              primaryFileObj.id,
              'executed-by',
              timestamp,
              'Process executed by file',
              created
            );
            yield relationship;
            createdRelationships.add(relationship.id);
            report.object_refs.push(relationship.id);
          }

          // Create indicator for process file
          const indicatorObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('indicator', `indicator-${processFileObj.id}`),
            type: 'indicator',
            pattern: processFileObj.pattern,
            pattern_type: 'stix',
            valid_from: created,
            description: `Indicator for process file: ${process.sha256}`,
          };
          const relationship = createRelationship(
            indicatorObj.id,
            processFileObj.id,
            'based-on',
            timestamp,
            'Indicator based on process file',
            created
          );
          yield indicatorObj;
          yield relationship;
          stixObjectMap[`indicator-${processFileObj.id}`] = indicatorObj;
          createdRelationships.add(relationship.id);
          report.object_refs.push(indicatorObj.id, relationship.id);
        } else if (process.sha256) {
          console.warn(`Invalid SHA-256 hash for process: ${process.sha256}`);
          const observedObj: GenericStixObject = {
            ...baseObj,
            id: generateStixId('observed-data', `process-${process.name || jobId}`),
            type: 'observed-data',
            number_observed: 1,
            first_observed: created,
            last_observed: modified,
            description: `Invalid process hash from Hybrid Analysis: ${process.sha256}`,
          };
          yield observedObj;
          stixObjectMap[`process-${process.name || jobId}`] = observedObj;
          report.object_refs.push(observedObj.id);
        }
      } catch (error) {
        console.error(`Error processing process ${process.name || 'unknown'}: ${(error as Error).message}`);
      }
    }

    // Create sightings for primary file, URL, domains, and IPs if threatScore > 0
    if (threatScore > 0) {
      const orgIdentity: GenericStixObject = stixObjectMap['hybrid-org'] || {
        id: generateStixId('identity', 'hybrid-org'),
        type: 'identity',
        spec_version: STIX_VERSION,
        name: 'Hybrid Analysis',
        identity_class: 'organization',
        created,
        modified,
        object_marking_refs: [tlpMarking.id],
      };
      if (!stixObjectMap['hybrid-org']) {
        yield orgIdentity;
        stixObjectMap['hybrid-org'] = orgIdentity;
        report.object_refs.push(orgIdentity.id);
      }

      const sightingCount = Math.floor(threatScore / 10) || 1; // Derive count from threatScore
      for (const objId of Object.keys(stixObjectMap)) {
        const obj = stixObjectMap[objId];
        if (STIX_SCO_TYPES.includes(obj.type) && !objId.startsWith('indicator-')) {
          const sighting = createSighting(
            obj.id,
            [orgIdentity.id],
            timestamp,
            sightingCount,
            `Sighting of ${obj.type} from Hybrid Analysis with threat score ${threatScore}`,
            obj.type === 'observed-data' ? [obj.id] : undefined,
            verdict === 'malicious'
          );
          yield sighting;
          report.object_refs.push(sighting.id);
        }
      }
    }

    // Yield observed-data if no primary file was created
    if (!primaryFileObj) {
      const observedObj: GenericStixObject = {
        ...baseObj,
        id: generateStixId('observed-data', jobId),
        type: 'observed-data',
        number_observed: 1,
        first_observed: created,
        last_observed: modified,
        description: `Fallback observed-data for Hybrid Analysis sample: ${jobId}`,
      };
      yield observedObj;
      stixObjectMap[jobId] = observedObj;
      report.object_refs.push(observedObj.id);
    }

    // Yield report last
    yield report;

    console.log(`Processed Hybrid Analysis sample ${jobId}, yielding STIX objects incrementally`);
  } catch (error) {
    console.error(`Hybrid Analysis mapper error: ${(error as Error).message}`, {
      raw: JSON.stringify(raw, null, 2).substring(0, 500),
    });
  }
}



export const objectMappers: Record<string, 
  ((raw: any) => GenericStixObject | GenericStixObject[]) | 
  ((raw: any) => Generator<GenericStixObject, void, unknown>)

> = {
  misp: (raw: any): Generator<GenericStixObject, void, unknown> => {
    return processMispData(raw);
  },



  alienVaultOTX: (raw: any): Generator<GenericStixObject, void, unknown> => {
    return processAlienVaultOTXPulse(raw);
  },
  hybridAnalysis: (raw: any): Generator<GenericStixObject, void, unknown> => {
    return processHybridAnalysis(raw);
  },
  // ... other mappers

};