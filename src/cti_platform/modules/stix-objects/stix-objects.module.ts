import { Module } from '@nestjs/common';
import { BundleService } from './bundle/bundle.service';
import { BundleResolver } from './bundle/bundle.resolver';
import { ArtifactService } from './cyber-observables/artifact/artifact.service';
import { ArtifactResolver } from './cyber-observables/artifact/artifact.resolver';
import { AutonomousSystemService } from './cyber-observables/autonomous-system/autonomous-system.service';
import { AutonomousSystemResolver } from './cyber-observables/autonomous-system/autonomous-system.resolver';
import { DirectoryService } from './cyber-observables/directory/directory.service';
import { DirectoryResolver } from './cyber-observables/directory/directory.resolver';
import { DomainNameService } from './cyber-observables/domain-name/domain-name.service';
import { DomainNameResolver } from './cyber-observables/domain-name/domain-name.resolver';
import { EmailAddressService } from './cyber-observables/email-address/email-address.service';
import { EmailAddressResolver } from './cyber-observables/email-address/email-address.resolver';
import { EmailMessageService } from './cyber-observables/email-message/email-message.service';
import { EmailMessageResolver } from './cyber-observables/email-message/email-message.resolver';
import { FileService } from './cyber-observables/file/file.service';
import { FileResolver } from './cyber-observables/file/file.resolver';
import { IPv4AddressService } from './cyber-observables/ipv4-address/ipv4-address.service';
import { IPv4AddressResolver } from './cyber-observables/ipv4-address/ipv4-address.resolver';
import { IPv6AddressService } from './cyber-observables/ipv6-address/ipv6-address.service';
import { IPv6AddressResolver } from './cyber-observables/ipv6-address/ipv6-address.resolver';
import { MACAddressService } from './cyber-observables/mac-address/mac-address.service';
import {MACAddressResolver } from './cyber-observables/mac-address/mac-address.resolver';
import { MutexService } from './cyber-observables/mutex/mutex.service';
import { MutexResolver } from './cyber-observables/mutex/mutex.resolver';
import { NetworkTrafficService } from './cyber-observables/network-traffic/network-traffic.service';
import { NetworkTrafficResolver } from './cyber-observables/network-traffic/network-traffic.resolver';
import { ProcessService } from './cyber-observables/process/process.service';
import { ProcessResolver } from './cyber-observables/process/process.resolver';
import { SoftwareService } from './cyber-observables/software/software.service';
import { SoftwareResolver } from './cyber-observables/software/software.resolver';
import { UrlService } from './cyber-observables/url/url.service';
import { UrlResolver } from './cyber-observables/url/url.resolver';
import { UserAccountService } from './cyber-observables/user-account/user-account.service';
import { UserAccountResolver } from './cyber-observables/user-account/user-account.resolver';
import { WindowsRegistryKeyService } from './cyber-observables/windows-registry-key/windows-registry-key.service';
import { WindowsRegistryKeyResolver } from './cyber-observables/windows-registry-key/windows-registry-key.resolver';
import { X509CertificateService } from './cyber-observables/x.509-certificate/x509-certificate.service';
import { X509CertificateResolver } from './cyber-observables/x.509-certificate/x509-certificate.resolver';
import { RelationshipService } from './relationships/relationship.service';
import { RelationshipResolver } from './relationships/relationship.resolver';
import { AttackPatternService } from './domain-objects/attack-pattern/attack-pattern.service';
import { AttackPatternResolver } from './domain-objects/attack-pattern/attack-pattern.resolver';
import { CampaignService } from './domain-objects/campaign/campaign.service';
import { CampaignResolver } from './domain-objects/campaign/campaign.resolver';
import { CourseOfActionService } from './domain-objects/course-of-action/course-of-action.service';
import { CourseOfActionResolver } from './domain-objects/course-of-action/course-of-action.resolver';
import { GroupingService } from './domain-objects/grouping/grouping.service';
import { GroupingResolver } from './domain-objects/grouping/grouping.resolver';
import { IdentityService } from './domain-objects/identity/identity.service';
import { IdentityResolver } from './domain-objects/identity/identity.resolver';
import { IncidentService } from './domain-objects/incident/incident.service';
import { IncidentResolver } from './domain-objects/incident/incident.resolver';
import { IndicatorService } from './domain-objects/indicator/indicator.service';
import { IndicatorResolver } from './domain-objects/indicator/indicator.resolver';
import { InfrastructureService } from './domain-objects/infrastructure/infrastructure.service';
import { InfrastructureResolver } from './domain-objects/infrastructure/infrastructure.resolver';
import { IntrusionSetService } from './domain-objects/intrusion-set/intrusion-set.service';
import { IntrusionSetResolver } from './domain-objects/intrusion-set/intrusion-set.resolver';
import { LocationService } from './domain-objects/location/location.service';
import { LocationResolver } from './domain-objects/location/location.resolver';
import { MalwareService } from './domain-objects/malware/malware.service';
import { MalwareResolver } from './domain-objects/malware/malware.resolver';
import { MalwareAnalysisService } from './domain-objects/malware-analysis/malware-analysis.service';
import { MalwareAnalysisResolver } from './domain-objects/malware-analysis/malware-analysis.resolver';
import { NoteService } from './domain-objects/note/note.service';
import { NoteResolver } from './domain-objects/note/note.resolver';
import { ObservedDataService } from './domain-objects/observed-data/observed-data.service';
import { ObservedDataResolver } from './domain-objects/observed-data/observed-data.resolver';
import { OpinionService } from './domain-objects/opinion/opinion.service';
import { OpinionResolver } from './domain-objects/opinion/opinion.resolver';
import { ReportService } from './domain-objects/report/report.service';
import { ReportResolver } from './domain-objects/report/report.resolver';
import { ThreatActorService } from './domain-objects/threat-actor/threat-actor.service';
import { ThreatActorResolver } from './domain-objects/threat-actor/threat-actor.resolver';
import { ToolService } from './domain-objects/tool/tool.service';
import { ToolResolver } from './domain-objects/tool/tool.resolver';
import { VulnerabilityService } from './domain-objects/vulnerability/vulnerability.service';
import { VulnerabilityResolver } from './domain-objects/vulnerability/vulnerability.resolver';
import { SightingService } from './sighting/sighting.service';
import { SightingResolver } from './sighting/sighting.resolver';
import { ConfigModule } from '@nestjs/config';
import { ConfigService } from '@nestjs/config';
import { Client } from '@opensearch-project/opensearch';
import opensearchConfig from 'src/cti_platform/config/opensearch.config';
@Module({
  imports: [// Global Configuration
        ConfigModule.forRoot({
          load: [opensearchConfig],
        }),],
  providers:[
    {
      provide: 'OPENSEARCH_CLIENT',
      useFactory: (configService: ConfigService) => {
        const opensearchHost = configService.get<string>('OPENSEARCH_HOST', 'http://localhost:9200');
        console.log(`[OpenSearch] Connecting to: ${opensearchHost}`);
        return new Client({ node: opensearchHost });
      },
      inject: [ConfigService],
    },
    BundleService, BundleResolver,
    ArtifactService, ArtifactResolver,
    AutonomousSystemService, AutonomousSystemResolver,
    DirectoryService, DirectoryResolver,
    DomainNameService, DomainNameResolver,
    EmailAddressService, EmailAddressResolver,
    EmailMessageService, EmailMessageResolver,
    FileService, FileResolver,
    IPv4AddressService, IPv4AddressResolver,
    IPv6AddressService, IPv6AddressResolver,
    MACAddressService, MACAddressResolver,
    MutexService, MutexResolver,
    NetworkTrafficService, NetworkTrafficResolver,
    ProcessService, ProcessResolver,
    SoftwareService, SoftwareResolver,
    UrlService, UrlResolver,
    UserAccountService, UserAccountResolver,
    WindowsRegistryKeyService, WindowsRegistryKeyResolver,
    X509CertificateService, X509CertificateResolver,
    RelationshipService, RelationshipResolver,
    AttackPatternService, AttackPatternResolver,
    CampaignService, CampaignResolver,
    CourseOfActionService, CourseOfActionResolver,
    GroupingService, GroupingResolver,
    IdentityService, IdentityResolver,
    IncidentService, IncidentResolver,
    IndicatorService, IndicatorResolver,
    InfrastructureService, InfrastructureResolver,
    IntrusionSetService, IntrusionSetResolver,
    LocationService, LocationResolver,
    MalwareService, MalwareResolver,
    MalwareAnalysisService, MalwareAnalysisResolver,
    NoteService, NoteResolver,
    ObservedDataService, ObservedDataResolver,
    OpinionService, OpinionResolver,
    ReportService, ReportResolver,
    ThreatActorService, ThreatActorResolver,
    ToolService, ToolResolver,
    VulnerabilityService, VulnerabilityResolver,
    SightingResolver, SightingService,
  ],
  exports: ['OPENSEARCH_CLIENT'],
})
export class StixObjectsModule {}
