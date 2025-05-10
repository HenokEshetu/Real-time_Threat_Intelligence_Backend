import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bull';
import { HttpModule } from '@nestjs/axios';
import { FeedIngesterService } from './feeds/feed.service';
import { BundleService } from '../stix-objects/bundle/bundle.service';
import { ArtifactService } from '../stix-objects/cyber-observables/artifact/artifact.service';
import { AutonomousSystemService } from '../stix-objects/cyber-observables/autonomous-system/autonomous-system.service';
import { DirectoryService } from '../stix-objects/cyber-observables/directory/directory.service';
import { DomainNameService } from '../stix-objects/cyber-observables/domain-name/domain-name.service';
import { EmailAddressService } from '../stix-objects/cyber-observables/email-address/email-address.service';
import { EmailMessageService } from '../stix-objects/cyber-observables/email-message/email-message.service';
import { FileService } from '../stix-objects/cyber-observables/file/file.service';
import { IPv4AddressService } from '../stix-objects/cyber-observables/ipv4-address/ipv4-address.service';
import { IPv6AddressService } from '../stix-objects/cyber-observables/ipv6-address/ipv6-address.service';
import { MACAddressService } from '../stix-objects/cyber-observables/mac-address/mac-address.service';
import { MutexService } from '../stix-objects/cyber-observables/mutex/mutex.service';
import { NetworkTrafficService } from '../stix-objects/cyber-observables/network-traffic/network-traffic.service';
import { ProcessService } from '../stix-objects/cyber-observables/process/process.service';
import { SoftwareService } from '../stix-objects/cyber-observables/software/software.service';
import { UrlService } from '../stix-objects/cyber-observables/url/url.service';
import { UserAccountService } from '../stix-objects/cyber-observables/user-account/user-account.service';
import { WindowsRegistryKeyService } from '../stix-objects/cyber-observables/windows-registry-key/windows-registry-key.service';
import { X509CertificateService } from '../stix-objects/cyber-observables/x.509-certificate/x509-certificate.service';
import { RelationshipService } from '../stix-objects/relationships/relationship.service';
import { AttackPatternService } from '../stix-objects/domain-objects/attack-pattern/attack-pattern.service';
import { CampaignService } from '../stix-objects/domain-objects/campaign/campaign.service';
import { CourseOfActionService } from '../stix-objects/domain-objects/course-of-action/course-of-action.service';
import { GroupingService } from '../stix-objects/domain-objects/grouping/grouping.service';
import { IdentityService } from '../stix-objects/domain-objects/identity/identity.service';
import { IncidentService } from '../stix-objects/domain-objects/incident/incident.service';
import { IndicatorService } from '../stix-objects/domain-objects/indicator/indicator.service';
import { InfrastructureService } from '../stix-objects/domain-objects/infrastructure/infrastructure.service';
import { IntrusionSetService } from '../stix-objects/domain-objects/intrusion-set/intrusion-set.service';
import { LocationService } from '../stix-objects/domain-objects/location/location.service';
import { MalwareService } from '../stix-objects/domain-objects/malware/malware.service';
import { MalwareAnalysisService } from '../stix-objects/domain-objects/malware-analysis/malware-analysis.service';
import { NoteService } from '../stix-objects/domain-objects/note/note.service';
import { ObservedDataService } from '../stix-objects/domain-objects/observed-data/observed-data.service';
import { OpinionService } from '../stix-objects/domain-objects/opinion/opinion.service';
import { ReportService } from '../stix-objects/domain-objects/report/report.service';
import { ThreatActorService } from '../stix-objects/domain-objects/threat-actor/threat-actor.service';
import { ToolService } from '../stix-objects/domain-objects/tool/tool.service';
import { VulnerabilityService } from '../stix-objects/domain-objects/vulnerability/vulnerability.service';
import { SightingService } from '../stix-objects/sighting/sighting.service';
import { EnrichmentService } from '../enrichment/enrichment.service';
import { LookupService } from 'src/cti_platform/core/utils/lookup.service';
import { FeedConfigService } from './feeds/feed-config.service';
import { StixObjectsModule } from '../stix-objects/stix-objects.module';
import { MarkingDefinitionService } from '../stix-objects/marking-definition/marking-definition.service';
import { MarkingDefinitionResolver } from '../stix-objects/marking-definition/marking-definition.resolver';
import { ScheduleModule } from '@nestjs/schedule';
import { AttackIngestionService } from './feeds/attack-stix-service';

@Module({
  imports: [
    BullModule.forRoot({
      redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT || '6379', 10),
      },
    }),
    BullModule.registerQueue({
      name: 'feedQueue', // Ensure this matches the queue name in @InjectQueue
    }),
    HttpModule, // Added to provide HttpService for EnrichmentService
    StixObjectsModule,
    ScheduleModule.forRoot(),
  ],
  providers: [
    AttackIngestionService,
    MarkingDefinitionService,
    MarkingDefinitionResolver,
    BundleService,
    ArtifactService,
    AutonomousSystemService,
    DirectoryService,
    DomainNameService,
    EmailAddressService,
    FeedIngesterService,
    EmailMessageService,
    FileService,
    IPv4AddressService,
    IPv6AddressService,
    MACAddressService,
    MutexService,
    NetworkTrafficService,
    ProcessService,
    SoftwareService,
    UrlService,
    UserAccountService,
    WindowsRegistryKeyService,
    X509CertificateService,
    RelationshipService,
    AttackPatternService,
    CampaignService,
    CourseOfActionService,
    GroupingService,
    IdentityService,
    IncidentService,
    IndicatorService,
    InfrastructureService,
    IntrusionSetService,
    LocationService,
    MalwareService,
    MalwareAnalysisService,
    NoteService,
    ObservedDataService,
    OpinionService,
    ReportService,
    ThreatActorService,
    ToolService,
    VulnerabilityService,
    SightingService,
    LookupService ,
    EnrichmentService,
    FeedConfigService, 
    
  ],
  exports: [FeedIngesterService]
})
export class IngestionFromApiFeedsModule {}