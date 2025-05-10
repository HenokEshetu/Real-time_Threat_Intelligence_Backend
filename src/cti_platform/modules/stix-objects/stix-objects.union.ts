import { createUnionType } from '@nestjs/graphql';
import { Artifact } from './cyber-observables/artifact/artifact.entity';
import { AutonomousSystem } from './cyber-observables/autonomous-system/autonomous-system.entity';
import { Directory } from './cyber-observables/directory/directory.entity';
import { DomainName } from './cyber-observables/domain-name/domain-name.entity';
import { EmailAddress } from './cyber-observables/email-address/email-address.entity';
import { EmailMessage } from './cyber-observables/email-message/email-message.entity';
import { File } from './cyber-observables/file/file.entity';
import { IPv4Address } from './cyber-observables/ipv4-address/ipv4-address.entity';
import { IPv6Address } from './cyber-observables/ipv6-address/ipv6-address.entity';
import { MACAddress } from './cyber-observables/mac-address/mac-address.entity';
import { Mutex } from './cyber-observables/mutex/mutex.entity';
import { NetworkTraffic } from './cyber-observables/network-traffic/network-traffic.entity';
import { Process } from './cyber-observables/process/process.entity';
import { Software } from './cyber-observables/software/software.entity';
import { Url } from './cyber-observables/url/url.entity';
import { UserAccount } from './cyber-observables/user-account/user-account.entity';
import { WindowsRegistryKey } from './cyber-observables/windows-registry-key/windows-registry-key.entity';
import { X509Certificate } from './cyber-observables/x.509-certificate/x509-certificate.entity';
import { AttackPattern } from './domain-objects/attack-pattern/attack-pattern.entity';
import { Campaign } from './domain-objects/campaign/campaign.entity';
import { CourseOfAction } from './domain-objects/course-of-action/course-of-action.entity';
import { Grouping } from './domain-objects/grouping/grouping.entity';
import { Identity } from './domain-objects/identity/identity.entity';
import { Incident } from './domain-objects/incident/incident.entity';
import { Indicator } from './domain-objects/indicator/indicator.entity';
import { Infrastructure } from './domain-objects/infrastructure/infrastructure.entity';
import { IntrusionSet } from './domain-objects/intrusion-set/intrusion-set.entity';
import { Location } from './domain-objects/location/location.entity';
import { MalwareAnalysis } from './domain-objects/malware-analysis/malware-analysis.entity';
import { Malware } from './domain-objects/malware/malware.entity';
import { Note } from './domain-objects/note/note.entity';
import { ObservedData } from './domain-objects/observed-data/observed-data.entity';
import { Opinion } from './domain-objects/opinion/opinion.entity';
import { Report } from './domain-objects/report/report.entity';
import { ThreatActor } from './domain-objects/threat-actor/threat-actor.entity';
import { Tool } from './domain-objects/tool/tool.entity';
import { Vulnerability } from './domain-objects/vulnerability/vulnerability.entity';
import { Sighting } from './sighting/sighting.entity';

// Define the GraphQL union type
export const StixObject = createUnionType({
  name: 'StixObject', // Name of the union in the GraphQL schema
  types: () => [
    Artifact,
    AttackPattern,
    AutonomousSystem,
    Campaign,
    CourseOfAction,
    Directory,
    DomainName,
    EmailAddress,
    EmailMessage,
    File,
    Grouping,
    IPv4Address,
    IPv6Address,
    Identity,
    Incident,
    Indicator,
    Infrastructure,
    IntrusionSet,
    Location,
    MACAddress,
    Malware,
    MalwareAnalysis,
    Mutex,
    NetworkTraffic,
    Note,
    ObservedData,
    Opinion,
    Process,
    Report,
    Sighting,
    Software,
    ThreatActor,
    Tool,
    Url,
    UserAccount,
    Vulnerability,
    WindowsRegistryKey,
    X509Certificate,
  ],
  resolveType: (value) => {
    // Determine the actual type based on the 'type' field in STIX objects
    switch (value.type) {
      case 'artifact':
        return Artifact;
      case 'attack-pattern':
        return AttackPattern;
      case 'autonomous-system':
        return AutonomousSystem;
      case 'campaign':
        return Campaign;
      case 'course-of-action':
        return CourseOfAction;
      case 'directory':
        return Directory;
      case 'domain-name':
        return DomainName;
      case 'email-addr':
        return EmailAddress;
      case 'email-message':
        return EmailMessage;
      case 'file':
        return File;
      case 'grouping':
        return Grouping;
      case 'ipv4-addr':
        return IPv4Address;
      case 'ipv6-addr':
        return IPv6Address;
      case 'identity':
        return Identity;
      case 'incident':
        return Incident;
      case 'indicator':
        return Indicator;
      case 'infrastructure':
        return Infrastructure;
      case 'intrusion-set':
        return IntrusionSet;
      case 'location':
        return Location;
      case 'mac-addr':
        return MACAddress;
      case 'malware':
        return Malware;
      case 'malware-analysis':
        return MalwareAnalysis;
      case 'mutex':
        return Mutex;
      case 'network-traffic':
        return NetworkTraffic;
      case 'note':
        return Note;
      case 'observed-data':
        return ObservedData;
      case 'opinion':
        return Opinion;
      case 'process':
        return Process;
      case 'report':
        return Report;
      case 'sighting':
        return Sighting;
      case 'software':
        return Software;
      case 'threat-actor':
        return ThreatActor;
      case 'tool':
        return Tool;
      case 'url':
        return Url;
      case 'user-account':
        return UserAccount;
      case 'vulnerability':
        return Vulnerability;
      case 'windows-registry-key':
        return WindowsRegistryKey;
      case 'x509-certificate':
        return X509Certificate;
      default:
        return null; // Return null if type is unknown
    }
  },
});

// Optionally, keep the TypeScript type for type safety
// export type StixObject =
//   | Artifact
//   | AttackPattern
//   | AutonomousSystem
//   | Campaign
//   | CourseOfAction
//   | Directory
//   | DomainName
//   | EmailAddress
//   | EmailMessage
//   | File
//   | Grouping
//   | IPv4Address
//   | IPv6Address
//   | Identity
//   | Incident
//   | Indicator
//   | Infrastructure
//   | IntrusionSet
//   | Location
//   | MACAddress
//   | Malware
//   | MalwareAnalysis
//   | Mutex
//   | NetworkTraffic
//   | Note
//   | ObservedData
//   | Opinion
//   | Process
//   | Report
//   | Sighting
//   | Software
//   | ThreatActor
//   | Tool
//   | Url
//   | UserAccount
//   | Vulnerability
//   | WindowsRegistryKey
//   | X509Certificate;
