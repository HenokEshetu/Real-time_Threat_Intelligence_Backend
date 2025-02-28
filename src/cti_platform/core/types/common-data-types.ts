import { Field, InputType, ObjectType, ID, registerEnumType } from '@nestjs/graphql';
import GraphQLJSON from 'graphql-type-json';
import { GraphQLJSONObject } from 'graphql-scalars';
import { DateTime } from '@opensearch-project/opensearch/api/_types/_common';
import { GraphQLDateTime } from 'graphql-scalars'; // Use GraphQL's DateTime scalar

// Basic Types
export type Binary = string; // Base64 encoded binary data
export type Hex = string; // Hex encoded binary data
export type Identifier = string; // STIX identifier pattern: [object-type]--[UUID]

// Dictionary Types
export type Dictionary = {
  [key: string]: any;
};

// Enums
export enum IdentityClass {
  INDIVIDUAL = 'individual',
  GROUP = 'group',
  SYSTEM = 'system',
  ORGANIZATION = 'organization',
  CLASS = 'class',
  UNKNOWN = 'unknown'
}

export enum IndustrySector {
  AGRICULTURE = 'agriculture',
  AEROSPACE = 'aerospace',
  AUTOMOTIVE = 'automotive',
  CHEMICAL = 'chemical',
  COMMERCIAL = 'commercial',
  COMMUNICATIONS = 'communications',
  CONSTRUCTION = 'construction',
  DEFENSE = 'defense',
  EDUCATION = 'education',
  ENERGY = 'energy',
  ENTERTAINMENT = 'entertainment',
  FINANCIAL_SERVICES = 'financial-services',
  GOVERNMENT = 'government',
  HEALTHCARE = 'healthcare',
  HOSPITALITY_LEISURE = 'hospitality-leisure',
  INFRASTRUCTURE = 'infrastructure',
  INSURANCE = 'insurance',
  MANUFACTURING = 'manufacturing',
  MINING = 'mining',
  NON_PROFIT = 'non-profit',
  PHARMACEUTICALS = 'pharmaceuticals',
  RETAIL = 'retail',
  TECHNOLOGY = 'technology',
  TELECOMMUNICATIONS = 'telecommunications',
  TRANSPORTATION = 'transportation',
  UTILITIES = 'utilities'
}

export enum LocationType {
  ADMINISTRATIVE_AREA = 'administrative-area',
  ASTRONOMICAL_OBJECT = 'astronomical-object',
  MARITIME_REGION = 'maritime-region',
  REGION = 'region',
  CONTINENT = 'continent',
  COUNTRY = 'country',
  CITY = 'city',
  UNKNOWN = 'unknown'
}

export enum PatternType {
  STIX = 'stix',
  PCRE = 'pcre',
  SIGMA = 'sigma',
  SNORT = 'snort',
  SURICATA = 'suricata',
  YARA = 'yara'
}

export enum IndicatorType {
  ANOMALOUS_ACTIVITY = 'anomalous-activity',
  ANONYMIZATION = 'anonymization',
  BENIGN = 'benign',
  COMPROMISED = 'compromised',
  MALICIOUS_ACTIVITY = 'malicious-activity',
  ATTRIBUTION = 'attribution',
  UNKNOWN = 'unknown'
}

export enum InfrastructureType {
  AMPLIFICATION = 'amplification',
  ANONYMIZATION = 'anonymization',
  BOTNET = 'botnet',
  COMMAND_AND_CONTROL = 'command-and-control',
  EXFILTRATION = 'exfiltration',
  HOSTING_MALWARE = 'hosting-malware',
  HOSTING_TARGET_LISTS = 'hosting-target-lists',
  PHISHING = 'phishing',
  RECONNAISSANCE = 'reconnaissance',
  STAGING = 'staging',
  UNKNOWN = 'unknown'
}

export enum MalwareType {
  ADWARE = 'adware',
  BACKDOOR = 'backdoor',
  BOT = 'bot',
  DDOS = 'ddos',
  DROPPER = 'dropper',
  EXPLOIT_KIT = 'exploit-kit',
  KEYLOGGER = 'keylogger',
  RANSOMWARE = 'ransomware',
  REMOTE_ACCESS_TROJAN = 'remote-access-trojan',
  RESOURCE_EXPLOITATION = 'resource-exploitation',
  ROGUE_SECURITY_SOFTWARE = 'rogue-security-software',
  ROOTKIT = 'rootkit',
  SCREEN_CAPTURE = 'screen-capture',
  SPYWARE = 'spyware',
  TROJAN = 'trojan',
  UNKNOWN = 'unknown',
  VIRUS = 'virus',
  WEBSHELL = 'webshell',
  WIPER = 'wiper',
  WORM = 'worm'
}

export enum ThreatActorType {
  ACTIVIST = 'activist',
  COMPETITOR = 'competitor',
  CRIME_SYNDICATE = 'crime-syndicate',
  CRIMINAL = 'criminal',
  HACKER = 'hacker',
  INSIDER_ACCIDENTAL = 'insider-accidental',
  INSIDER_DISGRUNTLED = 'insider-disgruntled',
  NATION_STATE = 'nation-state',
  SENSATIONALIST = 'sensationalist',
  SPY = 'spy',
  TERRORIST = 'terrorist',
  UNKNOWN = 'unknown'
}

export enum ToolType {
  DENIAL_OF_SERVICE = 'denial-of-service',
  EXPLOITATION = 'exploitation',
  INFORMATION_GATHERING = 'information-gathering',
  NETWORK_CAPTURE = 'network-capture',
  CREDENTIAL_EXPLOITATION = 'credential-exploitation',
  REMOTE_ACCESS = 'remote-access',
  VULNERABILITY_SCANNING = 'vulnerability-scanning',
  UNKNOWN = 'unknown'
}

// Register enums for GraphQL
registerEnumType(IdentityClass, { name: 'IdentityClass' });
registerEnumType(IndustrySector, { name: 'IndustrySector' });
registerEnumType(LocationType, { name: 'LocationType' });
registerEnumType(PatternType, { name: 'PatternType' });
registerEnumType(IndicatorType, { name: 'IndicatorType' });
registerEnumType(InfrastructureType, { name: 'InfrastructureType' });
registerEnumType(MalwareType, { name: 'MalwareType' });
registerEnumType(ThreatActorType, { name: 'ThreatActorType' });
registerEnumType(ToolType, { name: 'ToolType' });

// Complex Types
@ObjectType()

export class Hashes {
  @Field({ nullable: true })
  
  MD5?: string;

  @Field({ nullable: true })
  
  SHA_1?: string;

  @Field({ nullable: true })
  
  SHA_256?: string;

  @Field({ nullable: true })
  
  SHA_512?: string;

  [key: string]: string | undefined;
}

@ObjectType()

export class ExternalReference {
  @Field(() => ID)
  
  id: string;

  @Field()
  
  source_name: string;

  @Field({ nullable: true })
  
  description?: string;

  @Field({ nullable: true })
  
  url?: string;

  @Field(() => Hashes, { nullable: true })
 
  hashes?: Hashes;

  @Field({ nullable: true })
  
  external_id?: string;
}

@ObjectType()

export class KillChainPhase {
  @Field(() => ID)
 
  id: string;

  @Field()
  
  kill_chain_name: string;

  @Field()
  
  phase_name: string;
}

@ObjectType()

export class GranularMarking {
  @Field(() => ID)
 
  id: string;

  @Field({ nullable: true })
  
  lang?: string;

  @Field({ nullable: true })
 
  marking_ref?: string;

  @Field(() => [String])
  
  selectors: string[];
}

@ObjectType()

export class ExtensionDefinition {
  @Field(() => ID)
  
  id: string;

  @Field(() => ExtensionType)
  extension_type: ExtensionType;

  @Field()
  
  name: string;

  @Field({ nullable: true })
 
  description?: string;
  
  @Field(() => String)
  dateField: string;

  @Field(() => String)
  
  modified: string;

  @Field({ nullable: true })
 
  created_by_ref?: Identifier;

  @Field({ nullable: true })
  
  revoked?: boolean;

  @Field({ nullable: true })
  
  version?: string;

  @Field(() => GraphQLJSON)
  
  schema: Dictionary;

  @Field(() => [String], { nullable: true })
  
  extension_properties?: string[];
}

@ObjectType()
export abstract class CommonProperties {
  @Field()
  
  type: string;

  @Field()
 
  spec_version: '2.1';

  @Field(() => ID)
  
  id: Identifier;

  @Field({ nullable: true })
  
  created_by_ref?: Identifier;

  @Field(() => String)
   created: string;

  @Field(() => String)
  modified: string;


  @Field({ nullable: true })
  
  revoked?: boolean;

  @Field(() => [String], { nullable: true })
 
  labels?: string[];

  @Field({ nullable: true })
 
  confidence?: number;

  @Field({ nullable: true })
 
  lang?: string;

  @Field(() => [ExternalReference], { nullable: true })
  
  external_references?: ExternalReference[];

  @Field(() => [String], { nullable: true })
 
  object_marking_refs?: Identifier[];

  @Field(() => [GranularMarking], { nullable: true })
 
  granular_markings?: GranularMarking[];

  @Field(() => GraphQLJSON, { nullable: true })
 
  extensions?: {
    [key: string]: Dictionary;
  };
}

@ObjectType()
export abstract class CyberObservableCommonProperties extends CommonProperties {
  @Field({ nullable: true })
  
  defanged?: boolean;

  @Field(() => GraphQLJSON, { nullable: true })
 
  extensions?: {
    'extension-definition--*'?: Dictionary;
  };
}


export enum RelationshipType {
  DELIVERS = 'delivers',
  TARGETS = 'targets',
  USES = 'uses',
  ATTRIBUTED_TO = 'attributed-to',
  MITIGATES = 'mitigates',
  INDICATES = 'indicates',
  VARIANT_OF = 'variant-of',
  IMPERSONATES = 'impersonates',
  RELATED_TO = 'related-to',
  DERIVED_FROM = 'derived-from',
  CONSISTS_OF = 'consists-of',
  DUPLICATE_OF = 'duplicate-of',
  BELONGS_TO = 'belongs-to',
  COMPROMISES = 'compromises',
  ORIGINATES_FROM = 'originates-from',
  INVESTIGATES = 'investigates',
  LOCATED_AT = 'located-at',
  BASED_ON = 'based-on',
  COMMUNICATES_WITH = 'communicates-with',
  CONTROLS = 'controls',
  HAS = 'has',
  HOSTS = 'hosts',
  OWNS = 'owns',
  EXFILTRATE_TO = 'exfiltrate-to',
  DOWNLOADS = 'downloads',
  DROPS = 'drops',
  EXPLOITS = 'exploits',
  CHARACTERIZES = 'characterizes',
  ANALYSIS_OF = 'analysis-of',
  STATIC_ANALYSIS_OF = 'static-analysis-of',
  DYNAMIC_ANALYSIS_OF = 'dynamic-analysis-of',
}

// Register this enum with GraphQL
registerEnumType(RelationshipType, {
  name: 'RelationshipType',
  description: 'STIX Core Relationship Types',
});

  
  

  

@ObjectType()
export abstract class RelationshipCommonProperties extends CommonProperties {
  @Field(() => String) // 
  relationship_type: string;

  @Field(() => String, { nullable: true }) 
  description?: string;

  @Field(() => ID) //  Ensure Identifier is treated as a GraphQL ID
  source_ref: string;

  @Field(() => ID) 
  target_ref: string;

  
  @Field(() => String) 
  start_time?: string;

  @Field(() => String) 
  stop_time?: string;
}

  
// STIX Timestamp Precision Pattern
export type TimestampPrecision = 'year' | 'month' | 'day' | 'hour' | 'minute' | 'second';

// STIX Confidence Scale (0-100)
export type ConfidenceScale = number;

// STIX Object Types
export type STIXObjectType =
  | 'attack-pattern'
  | 'campaign'
  | 'course-of-action'
  | 'grouping'
  | 'identity'
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
  | 'relationship'
  | 'sighting'
  | 'marking-definition'
  | 'language-content'
  | 'bundle';

// STIX Object Marking Types
export type MarkingDefinitionType = 'statement' | 'tlp' | 'iep';

@ObjectType()
export class STIXPattern {
  @Field()
 
  pattern: string;

  @Field()
 
  pattern_type: PatternType;

  @Field({ nullable: true })
  
  pattern_version?: string;

  @Field(() => String) 
  
  
  valid_from?: string;

  @Field(() => String) 
  
  valid_until?: string;

  
}





@InputType()
export class HashesInput {
  @Field({ nullable: true })
  MD5?: string;

  @Field({ nullable: true })
  SHA_1?: string;

  @Field({ nullable: true })
  SHA_256?: string;

  @Field({ nullable: true })
  SHA_512?: string;

    // Add an index signature to allow dynamic properties
    [key: string]: string | undefined;
}

@InputType()
export class ExternalReferenceInput {
  @Field(() => ID)
  id: string;

  @Field()
  source_name: string;

  @Field({ nullable: true })
  description?: string;

  @Field({ nullable: true })
  url?: string;

  @Field(() => HashesInput, { nullable: true })
  hashes?: HashesInput;

  @Field({ nullable: true })
  external_id?: string;
}





@InputType()
export class KillChainPhaseInput {
  @Field(() => ID)
  id: string;

  @Field()
  kill_chain_name: string;

  @Field()
  phase_name: string;
}

@InputType()
export class GranularMarkingInput {
  @Field(() => ID)
  id: string;

  @Field({ nullable: true })
  lang?: string;

  @Field({ nullable: true })
  marking_ref?: string;

  @Field(() => [String])
  selectors: string[];
}



// Define the possible extension types as an Enum
export enum ExtensionType {
  NEW_SDO = 'new-sdo',
  NEW_SCO = 'new-sco',
  NEW_SRO = 'new-sro',
  PROPERTY_EXTENSION = 'property-extension',
}

// Register the Enum for GraphQL

registerEnumType(ExtensionType, { name: 'ExtensionType' });

@InputType()
export class ExtensionDefinitionInput {
  @Field(() => ID)
  id: string;

  @Field(() => ExtensionType)
  extension_type: ExtensionType;

  @Field()
  name: string;

  @Field({ nullable: true })
  description?: string;

  @Field(() => String) 
  created: string;

  @Field(() => String) 
  modified: string;

  @Field(() => ID, { nullable: true })
  created_by_ref?: string;

  @Field({ nullable: true })
  revoked?: boolean;

  @Field({ nullable: true })
  version?: string;

  @Field(() => GraphQLJSONObject)
  schema: Record<string, any>; // Dictionary type

  @Field(() => [String], { nullable: true })
  extension_properties?: string[];
}



@InputType()
export class CommonInput {
  @Field()
  type: string;

  @Field()
  spec_version: '2.1';

  @Field(() => ID)
  id: Identifier;

  @Field({ nullable: true })
  created_by_ref?: Identifier;

  @Field(() => String) 
  created: string;

  @Field(() => String) 
  modified: string;

  @Field({ nullable: true })
  revoked?: boolean;

  @Field(() => [String], { nullable: true })
  labels?: string[];

  @Field({ nullable: true })
  confidence?: number;

  @Field({ nullable: true })
  lang?: string;

  @Field(() => [ExternalReferenceInput], { nullable: true })
  external_references?: ExternalReferenceInput[];

  @Field(() => [String], { nullable: true })
  object_marking_refs?: Identifier[];

  @Field(() => [GranularMarkingInput], { nullable: true })
  granular_markings?: GranularMarkingInput[];

  @Field(() => GraphQLJSON, { nullable: true })
  extensions?: {
    [key: string]: Dictionary;
  };
}


@InputType()
export class CyberObservableCommonInput extends CommonInput {
  @Field({ nullable: true })
  defanged?: boolean;

  @Field(() => GraphQLJSON, { nullable: true })
  extensions?: {
    'extension-definition--*'?: Dictionary;
  };
}





@InputType()
export class RelationshipCommonInput extends CommonInput {
  @Field(() => RelationshipType)
  relationship_type: RelationshipType;
  @Field({ nullable: true })
  description?: string;

  @Field()
  source_ref: Identifier;

  @Field()
  target_ref: Identifier;

  @Field(() => String) 
  start_time?: string;
  @Field(() => String) 
  stop_time?: string;
}






@InputType()
export class STIXPatternInput {
  @Field()
  pattern: string;

  @Field()
  pattern_type: PatternType;

  @Field({ nullable: true })
  pattern_version?: string;

  @Field(() => String) 
  valid_from?: string;

  @Field(() => GraphQLDateTime)
  valid_until?: string;
}
