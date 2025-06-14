import { v4 as uuidv4 } from 'uuid';

// Generic default values for feed processing
export const DEFAULT_BATCH_SIZE = 60;
export const DEFAULT_TIMEOUT = 9000; // 5 seconds for faster DNS/ThreatFox queries
export const DEFAULT_RATE_LIMIT_DELAY = 1000; // 1 second
export const DEFAULT_MAX_RETRIES = 3;
export const DEFAULT_CONFIDENCE = 50; // Default confidence score for indicators
export const STIX_SPEC_VERSION = '2.1'; // STIX specification version

// Suspicious TLDs for warning (configurable)
export const SUSPICIOUS_TLDS = ['ru', 'su', 'cn', 'xyz', 'top', 'info'];

// Regular Expression Patterns for Indicator Validation
export const TYPE_PATTERNS = {
  // STIX 2.1 SCO Patterns
  'artifact': /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/, // MD5, SHA-1, SHA-256, SHA-512
  'autonomous-system': /^\d+$/, // ASN number
  'directory': /.+/, // Any non-empty string (path)
  'domain-name': /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}(?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61})*\.[a-zA-Z]{2,}$/, // Note: Relies on tldts in FeedUtils
  'email-address': /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  'email-message': /.+/, // Any non-empty string (message ID or header)
  'file': /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/, // MD5, SHA-1, SHA-256, SHA-512
  'ipv4-addr': /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  'ipv6-addr': /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::$/, // Supports compressed IPv6
  'mac-address': /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
  'mutex': /.+/, // Any non-empty string (mutex name)
  'network-traffic': /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/,
  'process': /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/, // MD5, SHA-1, SHA-256, SHA-512
  'software': /.+/, // Any non-empty string (software name)
  'url': /^(https?):\/\/([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?([/][^\s]*)?$/, // Stricter URL pattern
  'user-account': /.+/, // Any non-empty string (account ID)
  'windows-registry-key': /.+/, // Any non-empty string (registry key)
  'x509-certificate': /^[a-fA-F0-9:]+$/,
  // STIX 2.1 SDO Patterns
  'attack-pattern': /.+/,
  'campaign': /.+/,
  'course-of-action': /.+/,
  'identity': /.+/,
  'indicator': /.+/,
  'intrusion-set': /.+/,
  'malware': /.+/,
  'threat-actor': /.+/,
  'tool': /.+/,
  'vulnerability': /^CVE-\d{4}-\d{4,}$/,
  // OTX-Specific Patterns (kept for compatibility)
  'ipv4': /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  'ipv6': /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::$|^[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}::$/,
  'email': /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  'mac': /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
  'md5': /^[a-fA-F0-9]{32}$/,
  'sha1': /^[a-fA-F0-9]{40}$/,
  'sha256': /^[a-fA-F0-9]{64}$/,
  'sha512': /^[a-fA-F0-9]{128}$/,
  'domain': /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,}|xn--[A-Za-z0-9]+)$/,
};

// MITRE ATT&CK Kill Chain Mappings
export const MITRE_MAPPING = [
  {
    phase: 'reconnaissance',
    condition: (desc: string, type: string) =>
      desc.includes('scan') || desc.includes('probe') || type.includes('ip'),
  },
  {
    phase: 'resource-development',
    condition: (desc: string) => desc.includes('compile') || desc.includes('tool'),
  },
  {
    phase: 'initial-access',
    condition: (desc: string) => desc.includes('phish') || desc.includes('exploit'),
  },
  {
    phase: 'execution',
    condition: (desc: string, type: string) =>
      desc.includes('execute') || type === 'file' || desc.includes('malware'),
  },
  {
    phase: 'persistence',
    condition: (desc: string) => desc.includes('registry') || desc.includes('service'),
  },
  {
    phase: 'privilege-escalation',
    condition: (desc: string) => desc.includes('privilege') || desc.includes('elevate'),
  },
  {
    phase: 'defense-evasion',
    condition: (desc: string) => desc.includes('obfuscate') || desc.includes('encrypt'),
  },
  {
    phase: 'credential-access',
    condition: (desc: string) => desc.includes('credential') || desc.includes('password'),
  },
  {
    phase: 'discovery',
    condition: (desc: string) => desc.includes('discover') || desc.includes('enumerate'),
  },
  {
    phase: 'lateral-movement',
    condition: (desc: string) => desc.includes('lateral') || desc.includes('pivot'),
  },
  {
    phase: 'collection',
    condition: (desc: string) => desc.includes('collect') || desc.includes('harvest'),
  },
  {
    phase: 'command-and-control',
    condition: (desc: string, type: string) =>
      desc.includes('c2') || type === 'domain' || desc.includes('beacon'),
  },
  {
    phase: 'exfiltration',
    condition: (desc: string) => desc.includes('exfil') || desc.includes('upload'),
  },
  {
    phase: 'impact',
    condition: (desc: string) => desc.includes('destroy') || desc.includes('ransom'),
  },
];

// Lockheed Martin Cyber Kill Chain Mappings
export const LOCKHEED_MAPPING = [
  {
    phase: 'reconnaissance',
    condition: (type: string, desc: string) =>
      type.includes('ip') || desc.includes('scan') || desc.includes('recon'),
  },
  {
    phase: 'weaponization',
    condition: (type: string, desc: string) =>
      type === 'file' || desc.includes('payload') || desc.includes('weapon'),
  },
  {
    phase: 'delivery',
    condition: (type: string, desc: string) =>
      type === 'email' || desc.includes('deliver') || desc.includes('phish'),
  },
  {
    phase: 'exploitation',
    condition: (type: string, desc: string) =>
      type === 'vulnerability' || desc.includes('exploit') || desc.includes('vuln'),
  },
  {
    phase: 'installation',
    condition: (type: string, desc: string) =>
      type === 'file' || desc.includes('install') || desc.includes('dropper'),
  },
  {
    phase: 'command-and-control',
    condition: (type: string, desc: string) =>
      type === 'domain' || desc.includes('c2') || desc.includes('control'),
  },
  {
    phase: 'actions-on-objectives',
    condition: (type: string, desc: string) =>
      desc.includes('exfil') || desc.includes('ransom') || desc.includes('impact'),
  },
];

// Implementation Languages
export const IMPLEMENTATION_LANGUAGES: string[] = [
  'c',
  'c++',
  'c#',
  'java',
  'javascript',
  'python',
  'ruby',
  'golang',
  'powershell',
  'php',
  'rust',
  'perl',
  'vbscript',
];

// Architectures
export const ARCHITECTURES: string[] = [
  'x86',
  'x86_64',
  'arm',
  'arm64',
  'mips',
  'ppc',
  'sparc',
];

// Motivations
export const MOTIVATIONS = {
  PRIMARY: [
    'financial-gain',
    'espionage',
    'ideology',
    'destruction',
    'political',
    'competitive',
    'revenge',
    'unknown',
  ],
  SECONDARY: [
    'reputation-gain',
    'destruction',
    'ideology',
    'attention-seeking',
    'fear',
    'revenge',
    'disruption',
    'social-impact',
    'competitive',
    'financial-pressure',
    'testing',
  ],
};

// TLP Markings aligned with STIX 2.1
export const TLP_MARKINGS: Record<string, { id: string; definition: { tlp: string }; description: string }> = {
  WHITE: {
    id: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
    definition: { tlp: 'WHITE' },
    description: 'Unlimited sharing, no restrictions.',
  },
  GREEN: {
    id: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
    definition: { tlp: 'GREEN' },
    description: 'Share within the community, not publicly.',
  },
  AMBER: {
    id: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
    definition: { tlp: 'AMBER' },
    description: 'Limited sharing, need-to-know basis.',
  },
  RED: {
    id: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
    definition: { tlp: 'RED' },
    description: 'No sharing outside the immediate recipients.',
  },
};

// STIX-specific Kill Chain Definitions
export const STIX_KILL_CHAINS = {
  MITRE_ATTACK: 'mitre-attack',
  LOCKHEED_CYBER_KILL_CHAIN: 'lockheed-martin-cyber-kill-chain',
};