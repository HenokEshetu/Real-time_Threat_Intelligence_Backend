import { Injectable, Inject, Logger, OnModuleInit } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { SchedulerRegistry } from '@nestjs/schedule';
import { CronJob } from 'cron';
import { Readable, Transform } from 'stream';
import { pipeline } from 'stream/promises';
import * as StreamJSON from 'stream-json';
import { streamValues } from 'stream-json/streamers/StreamValues';
import { ArtifactService } from '../../stix-objects/cyber-observables/artifact/artifact.service';
import { AutonomousSystemService } from '../../stix-objects/cyber-observables/autonomous-system/autonomous-system.service';
import { DirectoryService } from '../../stix-objects/cyber-observables/directory/directory.service';
import { DomainNameService } from '../../stix-objects/cyber-observables/domain-name/domain-name.service';
import { EmailAddressService } from '../../stix-objects/cyber-observables/email-address/email-address.service';
import { EmailMessageService } from '../../stix-objects/cyber-observables/email-message/email-message.service';
import { FileService } from '../../stix-objects/cyber-observables/file/file.service';
import { IPv4AddressService } from '../../stix-objects/cyber-observables/ipv4-address/ipv4-address.service';
import { IPv6AddressService } from '../../stix-objects/cyber-observables/ipv6-address/ipv6-address.service';
import { MACAddressService } from '../../stix-objects/cyber-observables/mac-address/mac-address.service';
import { MutexService } from '../../stix-objects/cyber-observables/mutex/mutex.service';
import { NetworkTrafficService } from '../../stix-objects/cyber-observables/network-traffic/network-traffic.service';
import { ProcessService } from '../../stix-objects/cyber-observables/process/process.service';
import { SoftwareService } from '../../stix-objects/cyber-observables/software/software.service';
import { UrlService } from '../../stix-objects/cyber-observables/url/url.service';
import { UserAccountService } from '../../stix-objects/cyber-observables/user-account/user-account.service';
import { WindowsRegistryKeyService } from '../../stix-objects/cyber-observables/windows-registry-key/windows-registry-key.service';
import { X509CertificateService } from '../../stix-objects/cyber-observables/x.509-certificate/x509-certificate.service';
import { RelationshipService } from '../../stix-objects/relationships/relationship.service';
import { AttackPatternService } from '../../stix-objects/domain-objects/attack-pattern/attack-pattern.service';
import { CampaignService } from '../../stix-objects/domain-objects/campaign/campaign.service';
import { CourseOfActionService } from '../../stix-objects/domain-objects/course-of-action/course-of-action.service';
import { GroupingService } from '../../stix-objects/domain-objects/grouping/grouping.service';
import { IdentityService } from '../../stix-objects/domain-objects/identity/identity.service';
import { IncidentService } from '../../stix-objects/domain-objects/incident/incident.service';
import { IndicatorService } from '../../stix-objects/domain-objects/indicator/indicator.service';
import { InfrastructureService } from '../../stix-objects/domain-objects/infrastructure/infrastructure.service';
import { IntrusionSetService } from '../../stix-objects/domain-objects/intrusion-set/intrusion-set.service';
import { LocationService } from '../../stix-objects/domain-objects/location/location.service';
import { MalwareService } from '../../stix-objects/domain-objects/malware/malware.service';
import { MalwareAnalysisService } from '../../stix-objects/domain-objects/malware-analysis/malware-analysis.service';
import { NoteService } from '../../stix-objects/domain-objects/note/note.service';
import { ObservedDataService } from '../../stix-objects/domain-objects/observed-data/observed-data.service';
import { OpinionService } from '../../stix-objects/domain-objects/opinion/opinion.service';
import { ReportService } from '../../stix-objects/domain-objects/report/report.service';
import { ThreatActorService } from '../../stix-objects/domain-objects/threat-actor/threat-actor.service';
import { ToolService } from '../../stix-objects/domain-objects/tool/tool.service';
import { VulnerabilityService } from '../../stix-objects/domain-objects/vulnerability/vulnerability.service';
import { SightingService } from '../../stix-objects/sighting/sighting.service';
import { MarkingDefinitionService } from '../../stix-objects/marking-definition/marking-definition.service';
import { BundleService } from '../../stix-objects/bundle/bundle.service';

const DATA_URL = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json';
const UPDATE_CHECK_CRON = '0 */12 * * *'; // Every 12 hours
const STATE_INDEX = 'ingestion-state';

@Injectable()
export class AttackIngestionService implements OnModuleInit {
  private readonly logger = new Logger(AttackIngestionService.name);
  private initialized = false;

  constructor(
    @Inject('OPENSEARCH_CLIENT') private readonly openSearchService: Client,
    private readonly schedulerRegistry: SchedulerRegistry,
    private readonly fileService: FileService,
    private readonly attackPatternService: AttackPatternService,
    private readonly courseOfActionService: CourseOfActionService,
    private readonly identityService: IdentityService,
    private readonly markingDefinitionService: MarkingDefinitionService,
    private readonly relationshipService: RelationshipService,
    private readonly observedDataService: ObservedDataService,
    private readonly sightingService: SightingService,
    private readonly malwareService: MalwareService,
    private readonly malwareAnalysisService: MalwareAnalysisService,
    private readonly threatActorService: ThreatActorService,
    private readonly intrusionSetService: IntrusionSetService,
    private readonly campaignService: CampaignService,
    private readonly incidentService: IncidentService,
    private readonly indicatorService: IndicatorService,
    private readonly infrastructureService: InfrastructureService,
    private readonly toolService: ToolService,
    private readonly vulnerabilityService: VulnerabilityService,
    private readonly reportService: ReportService,
    private readonly noteService: NoteService,
    private readonly opinionService: OpinionService,
    private readonly groupingService: GroupingService,
    private readonly locationService: LocationService,
    private readonly directoryService: DirectoryService,
    private readonly domainNameService: DomainNameService,
    private readonly emailAddressService: EmailAddressService,
    private readonly emailMessageService: EmailMessageService,
    private readonly ipv4AddressService: IPv4AddressService,
    private readonly ipv6AddressService: IPv6AddressService,
    private readonly macAddressService: MACAddressService,
    private readonly mutexService: MutexService,
    private readonly networkTrafficService: NetworkTrafficService,
    private readonly processService: ProcessService,
    private readonly softwareService: SoftwareService,
    private readonly urlService: UrlService,
    private readonly userAccountService: UserAccountService,
    private readonly windowsRegistryKeyService: WindowsRegistryKeyService,
    private readonly x509CertificateService: X509CertificateService,
    private readonly autonomousSystemService: AutonomousSystemService,
    private readonly artifactService: ArtifactService,
    private readonly bundleService: BundleService,
  ) {}

  async onModuleInit() {
    await this.initializeState();
    this.scheduleUpdates();
    this.startInitialIngestion().catch((error) => {
      this.logger.error('Async initial ingestion failed', error.stack);
    });
  }

  private async initializeState() {
    try {
      await this.openSearchService.indices.create(
        {
          index: STATE_INDEX,
          body: {
            mappings: {
              properties: {
                last_modified: { type: 'date' },
                etag: { type: 'keyword' },
                last_fetched: { type: 'date' },
              },
            },
          },
        },
        { ignore: [400] },
      );
      this.logger.log('Ingestion state index initialized');
    } catch (error) {
      this.logger.error('Failed to initialize state index', error.stack);
      throw error;
    }
  }

  private async startInitialIngestion() {
    try {
      const state = await this.getIngestionState();
      if (!state) {
        this.logger.log('No existing ingestion state detected. Performing initial ingestion...');
        await this.performIngestion();
        this.logger.log('Initial ingestion completed successfully');
        this.initialized = true;
      } else {
        this.logger.log('Existing ingestion state found. Checking for updates...');
        await this.checkForUpdates();
        this.initialized = true;
      }
    } catch (error) {
      this.logger.error('Initial ingestion failed', error.stack);
      throw error;
    }
  }

  private async performIngestion() {
    try {
      this.logger.log(`Fetching data from ${DATA_URL}`);
      const response = await fetch(DATA_URL);
      if (!response.ok) throw new Error(`Failed to fetch data: ${response.status} ${response.statusText}`);
      const lastModified = response.headers.get('last-modified');
      const etag = response.headers.get('etag');
      if (!response.body) throw new Error('Response body unavailable');
      const readableStream = Readable.from(response.body as any);
      await this.processStream(readableStream);
      await this.updateIngestionState({
        last_modified: lastModified,
        etag,
        last_fetched: new Date().toISOString(),
      });
      this.logger.log('Data ingestion completed successfully');
    } catch (error) {
      this.logger.error('Data ingestion failed', error.stack);
      throw error;
    }
  }

  private async checkForUpdates() {
    try {
      const currentState = await this.getIngestionState();
      if (!currentState) return;
      this.logger.log('Checking for updates...');
      const response = await fetch(DATA_URL, { method: 'HEAD' });
      if (!response.ok) throw new Error(`HEAD request failed: ${response.status} ${response.statusText}`);
      const remoteLastModified = response.headers.get('last-modified');
      const remoteETag = response.headers.get('etag');
      if (remoteETag !== currentState.etag || remoteLastModified !== currentState.last_modified) {
        this.logger.log('New data version detected. Starting update...');
        await this.performIngestion();
      } else {
        this.logger.log('No updates available - data is current');
      }
    } catch (error) {
      this.logger.error('Update check failed', error.stack);
    }
  }

  private scheduleUpdates() {
    const job = new CronJob(UPDATE_CHECK_CRON, async () => {
      if (this.initialized) {
        this.logger.log('Running scheduled update check...');
        await this.checkForUpdates();
      }
    });
    this.schedulerRegistry.addCronJob('attack-data-updates', job);
    job.start();
    this.logger.log(`Scheduled update checks with cron pattern: ${UPDATE_CHECK_CRON}`);
  }

  private async getIngestionState(): Promise<{ last_modified: string; etag: string; last_fetched: string } | null> {
    try {
      const response = await this.openSearchService.search({
        index: STATE_INDEX,
        body: {
          size: 1,
          sort: [{ last_fetched: { order: 'desc' } }],
        },
      });
      const source = response.body.hits.hits[0]?._source;
      if (source && source.last_modified && source.etag && source.last_fetched) {
        return source as { last_modified: string; etag: string; last_fetched: string };
      }
      return null;
    } catch (error) {
      this.logger.error('Failed to retrieve ingestion state', error.stack);
      return null;
    }
  }

  private async updateIngestionState(state: { last_modified?: string; etag?: string; last_fetched: string }) {
    try {
      await this.openSearchService.index({
        index: STATE_INDEX,
        body: {
          last_modified: state.last_modified,
          etag: state.etag,
          last_fetched: state.last_fetched,
        },
        refresh: true,
      });
      this.logger.log('Ingestion state updated');
    } catch (error) {
      this.logger.error('Failed to update ingestion state', error.stack);
      throw error;
    }
  }

  private async processStream(readableStream: Readable): Promise<void> {
    const parser = StreamJSON.parser();
    const valueStreamer = streamValues();
    let objectCount = 0;

    const objectProcessor = new Transform({
      objectMode: true,
      transform: async (chunk, encoding, callback) => {
        try {
          const obj = chunk.value;
          //this.logger.debug(`Received object: ${JSON.stringify(obj, null, 2).substring(0, 100)}...`);

          if (obj && obj.type) {
            this.logger.log(`Processing object of type: ${obj.type}`);
            await this.processStixObject(obj);
            objectCount++;
          } else {
            this.logger.warn('Skipping invalid object');
          }

          callback();
        } catch (error) {
          this.logger.error(`Object processing error: ${error.message}`, error.stack);
          callback(); // Continue processing
        }
      },
      final: () => {
        this.logger.log(`Processed ${objectCount} STIX objects`);
      },
    });

    await pipeline(readableStream, parser, valueStreamer, objectProcessor);
  }

  private async processStixObject(obj: any): Promise<void> {
    // Handle bundle container (STIX type but should not be stored)
    if (obj.type === 'bundle') {
      this.logger.debug(`Processing bundle container ${obj.id}`);
      await this.processBundleContents(obj);
      return;
    }
  
    // Validate STIX 2.1 object requirements
    if (!this.isValidStixObject(obj)) {
      this.logger.warn(`Skipping non-STIX object: ${JSON.stringify(obj, null, 2).substring(0, 200)}`);
      return;
    }
  
    // Store all proper STIX objects
    try {
      const service = this.getServiceForType(obj.type);
      if (service) {
        this.logger.debug(`Storing STIX ${obj.type} ${obj.id}`);
        await service.create(obj);
        this.logger.log(`Successfully stored ${obj.type} ${obj.id}`);
      }
    } catch (error) {
      this.logger.error(`Failed to store ${obj.type} ${obj.id}: ${error.message}`);
    }
  }

  private async processBundleContents(bundle: any) {
    if (!bundle.objects || !Array.isArray(bundle.objects)) {
      this.logger.warn('Invalid bundle structure - missing objects array');
      return;
    }
  
    this.logger.log(`Processing bundle with ${bundle.objects.length} contained objects`);
    
    // Process all objects in parallel while maintaining order
    await Promise.allSettled(
      bundle.objects.map((obj: any) => 
        this.processStixObject(obj).catch(error => 
          this.logger.error(`Error processing object ${obj.id}: ${error.message}`)
        )
      )
    );
  }

  private isValidStixObject(obj: any): boolean {
    // Required STIX 2.1 core properties
    const requiredProps = ['type', 'id', 'created', 'modified', 'spec_version'];
    const hasRequired = requiredProps.every(prop => prop in obj);
    
    // Validate STIX spec version
    const validSpecVersion = obj.spec_version === '2.1';
    
    // Explicitly exclude bundle type from storage
    const isValidType = obj.type !== 'bundle' && this.getServiceForType(obj.type);
  
    return hasRequired && validSpecVersion && isValidType;
  }

  private getServiceForType(type: string): any {
    switch (type) {
      case 'file':
        return this.fileService;
      case 'attack-pattern':
        return this.attackPatternService;
      case 'course-of-action':
        return this.courseOfActionService;
      case 'identity':
        return this.identityService;
      case 'marking-definition':
        return this.markingDefinitionService;
      case 'relationship':
        return this.relationshipService;
      case 'observed-data':
        return this.observedDataService;
      case 'sighting':
        return this.sightingService;
      case 'malware':
        return this.malwareService;
      case 'malware-analysis':
        return this.malwareAnalysisService;
      case 'threat-actor':
        return this.threatActorService;
      case 'intrusion-set':
        return this.intrusionSetService;
      case 'campaign':
        return this.campaignService;
      case 'incident':
        return this.incidentService;
      case 'indicator':
        return this.indicatorService;
      case 'infrastructure':
        return this.infrastructureService;
      case 'tool':
        return this.toolService;
      case 'vulnerability':
        return this.vulnerabilityService;
      case 'report':
        return this.reportService;
      case 'note':
        return this.noteService;
      case 'opinion':
        return this.opinionService;
      case 'grouping':
        return this.groupingService;
      case 'location':
        return this.locationService;
      case 'directory':
        return this.directoryService;
      case 'domain-name':
        return this.domainNameService;
      case 'email-addr':
        return this.emailAddressService;
      case 'email-message':
        return this.emailMessageService;
      case 'ipv4-addr':
        return this.ipv4AddressService;
      case 'ipv6-addr':
        return this.ipv6AddressService;
      case 'mac-addr':
        return this.macAddressService;
      case 'mutex':
        return this.mutexService;
      case 'network-traffic':
        return this.networkTrafficService;
      case 'process':
        return this.processService;
      case 'software':
        return this.softwareService;
      case 'url':
        return this.urlService;
      case 'user-account':
        return this.userAccountService;
      case 'windows-registry-key':
        return this.windowsRegistryKeyService;
        
      case 'x509-certificate':
        return this.x509CertificateService;
      case 'autonomous-system':
        return this.autonomousSystemService;
      case 'artifact':
        return this.artifactService;
      case 'x-mitre-matrix':
      case 'x-mitre-tactic':
      case 'x-mitre-data-source':
      case 'x-mitre-data-component':
        this.logger.warn(`Skipping custom MITRE type: ${type}`);
        return null;
      default:
        this.logger.warn(`No service available for type: ${type}`);
        return null;
    }
  }
}