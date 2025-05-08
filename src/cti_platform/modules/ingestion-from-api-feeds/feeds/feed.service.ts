import { LookupService } from '../../../core/utils/lookup.service';
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
import { EnrichmentService } from '../../enrichment/enrichment.service';
import { MarkingDefinitionService } from '../../stix-objects/marking-definition/marking-definition.service';
import { Injectable, InternalServerErrorException, OnModuleInit, Logger } from '@nestjs/common';
import { InjectQueue, Process, Processor } from '@nestjs/bull';
import { Queue, Job } from 'bull';
import axios, { AxiosError } from 'axios';
import Bottleneck from 'bottleneck';
import { v4 as uuidv4 } from 'uuid';
import { FeedProviderConfig, GenericStixObject, EnrichmentData, StixType, ENRICHMENT_EXTENSIONS, } from './feed.types';
import { FeedConfigService } from './feed-config.service';
import { objectMappers } from './feed-mappers';


import {
  DEFAULT_BATCH_SIZE,
  DEFAULT_TIMEOUT,
  DEFAULT_RATE_LIMIT_DELAY,
  DEFAULT_MAX_RETRIES,
  TLP_MARKINGS,
  STIX_SPEC_VERSION,
} from './feed.constants';




type EnrichmentServiceKey =
  | 'geo'
  | 'whois'
  | 'virustotal'
  | 'abuseipdb'
  | 'shodan'
  | 'threatfox'
  | 'dns'
  | 'ssl'
  | 'asn'
  | 'hybrid'
  | 'threatcrowd'
  | 'misp';

  
  interface StixService<T> {
    create(input: T): Promise<{ id: string; [key: string]: any }>;
  }
  
  
  @Processor('feedQueue')
@Injectable()
export class FeedIngesterService implements OnModuleInit {
  private readonly logger = new Logger(FeedIngesterService.name);
  private readonly concurrency: number = parseInt(process.env.FEED_CONCURRENCY || '10', 10);
  private readonly defaultSchedule: string = process.env.FEED_SCHEDULE || '*/59 * * * *';
  private readonly defaultTimeout: number = parseInt(process.env.FEED_TIMEOUT || `${DEFAULT_TIMEOUT}`, 10);
  private readonly limiters: Map<string, Bottleneck> = new Map();
  private readonly debugLogging: boolean = process.env.DEBUG_LOGGING === 'true';
  
    private readonly serviceFactory: Map<StixType, StixService<any>> = new Map<StixType, StixService<any>>([
      ['artifact', this.artifactService],
      ['autonomous-system', this.autonomousSystemService],
      ['directory', this.directoryService],
      ['domain-name', this.domainNameService],
      ['email-addr', this.emailAddressService],
      ['email-message', this.emailMessageService],
      ['file', this.fileService],
      ['ipv4-addr', this.ipv4AddressService],
      ['ipv6-addr', this.ipv6AddressService],
      ['mac-address', this.macAddressService],
      ['mutex', this.mutexService],
      ['network-traffic', this.networkTrafficService],
      ['process', this.processService],
      ['software', this.softwareService],
      ['url', this.urlService],
      ['user-account', this.userAccountService],
      ['windows-registry-key', this.windowsRegistryKeyService],
      ['x509-certificate', this.x509CertificateService],
      ['attack-pattern', this.attackPatternService],
      ['campaign', this.campaignService],
      ['course-of-action', this.courseOfActionService],
      ['grouping', this.groupingService],
      ['identity', this.identityService],
      ['incident', this.incidentService],
      ['indicator', this.indicatorService],
      ['infrastructure', this.infrastructureService],
      ['intrusion-set', this.intrusionSetService],
      ['location', this.locationService],
      ['malware', this.malwareService],
      ['malware-analysis', this.malwareAnalysisService],
      ['note', this.noteService],
      ['observed-data', this.observedDataService],
      ['opinion', this.opinionService],
      ['report', this.reportService],
      ['threat-actor', this.threatActorService],
      ['tool', this.toolService],
      ['vulnerability', this.vulnerabilityService],
      ['sighting', this.sightingService],
      ['relationship', this.relationshipService],
      ['marking-definition', this.markingDefinitionService],
    ]);
  
    constructor(
      private readonly artifactService: ArtifactService,
      private readonly autonomousSystemService: AutonomousSystemService,
      private readonly directoryService: DirectoryService,
      private readonly domainNameService: DomainNameService,
      private readonly emailAddressService: EmailAddressService,
      private readonly emailMessageService: EmailMessageService,
      private readonly fileService: FileService,
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
      private readonly relationshipService: RelationshipService,
      private readonly attackPatternService: AttackPatternService,
      private readonly campaignService: CampaignService,
      private readonly courseOfActionService: CourseOfActionService,
      private readonly groupingService: GroupingService,
      private readonly identityService: IdentityService,
      private readonly incidentService: IncidentService,
      private readonly indicatorService: IndicatorService,
      private readonly infrastructureService: InfrastructureService,
      private readonly intrusionSetService: IntrusionSetService,
      private readonly locationService: LocationService,
      private readonly malwareService: MalwareService,
      private readonly malwareAnalysisService: MalwareAnalysisService,
      private readonly noteService: NoteService,
      private readonly observedDataService: ObservedDataService,
      private readonly opinionService: OpinionService,
      private readonly reportService: ReportService,
      private readonly threatActorService: ThreatActorService,
      private readonly toolService: ToolService,
      private readonly vulnerabilityService: VulnerabilityService,
      private readonly sightingService: SightingService,
      private readonly markingDefinitionService: MarkingDefinitionService,
      private readonly lookupService: LookupService,
      @InjectQueue('feedQueue') private readonly feedQueue: Queue,
      private readonly enrichmentService: EnrichmentService,
      private readonly feedConfigService: FeedConfigService,
    ) {}
  
    async onModuleInit() {
      try {
        await this.clearQueue();
        await this.initializeLimiters();
        await this.triggerImmediateFetch();
        await this.scheduleFeedProcessing();
        this.logger.log('Feed Ingester Service initialized');
      } catch (error) {
        this.logger.error('Failed to initialize Feed Ingester Service', error);
      }
    }


    private async clearQueue() {
    try {
      await this.feedQueue.obliterate({ force: true });
      await Promise.all([
        this.feedQueue.clean(0, 'active'),
        this.feedQueue.clean(0, 'wait'),
        this.feedQueue.clean(0, 'completed'),
        this.feedQueue.clean(0, 'failed'),
        this.feedQueue.clean(0, 'delayed'),
      ]);
    } catch (error) {
      this.logger.error('Failed to clear queue', error);
    }
  }
  
    private async initializeLimiters() {
      try {
        const configs = await this.feedConfigService.getAllConfigs();
        if (!configs.length) {
          this.logger.warn('No feed configurations found for limiters');
          return;
        }
        for (const config of configs) {
          this.limiters.set(
            config.id,
            new Bottleneck({
              maxConcurrent: 1,
              minTime: config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY,
            }),
          );
        }
        this.logger.log(`Initialized ${this.limiters.size} rate limiters`);
      } catch (error) {
        this.logger.error('Failed to initialize limiters', { error: error.message, stack: error.stack });
      }
    }
  
    private async triggerImmediateFetch(): Promise<void> {
      try {
        this.logger.log('Triggering immediate fetch for all feeds');
        const configs = await this.feedConfigService.getAllConfigs();
        this.logger.log(`Found ${configs.length} feed configurations`, { configIds: configs.map(c => c.id) });
        if (!configs.length) {
          this.logger.warn('No feed configurations found for immediate fetch');
          return;
        }
        const existingJobs = await this.feedQueue.getActive();
        if (existingJobs.some(job => job.name === 'processAllFeeds')) {
          this.logger.warn('processAllFeeds job already active, skipping immediate fetch');
          return;
        }
        const jobId = `immediate-fetch-${uuidv4()}`;
        await this.feedQueue.add(
          'processAllFeeds',
          {},
          { jobId, removeOnComplete: true, removeOnFail: true },
        );
        this.logger.log(`Queued immediate fetch job ${jobId}`);
        await this.getQueueStatus();
      } catch (error) {
        this.logger.error('Failed to trigger immediate fetch', { error: error.message, stack: error.stack });
      }
    }
  
    private async scheduleFeedProcessing(): Promise<void> {
      try {
        const configs = await this.feedConfigService.getAllConfigs();
        if (!configs.length) {
          this.logger.warn('No feed configurations found for scheduling');
          return;
        }
        for (const config of configs) {
          const schedule = config.schedule || this.defaultSchedule;
          const jobId = `feed-${config.id}-${uuidv4()}`;
          const repeatableJobs = await this.feedQueue.getRepeatableJobs();
          const existingJob = repeatableJobs.find(job => job.name === `processFeed:${config.id}`);
          if (existingJob) {
            this.logger.log(`Repeatable job for ${config.id} already exists`, { jobId: existingJob.id, cron: existingJob.cron });
            continue;
          }
          await this.feedQueue.add(
            `processFeed:${config.id}`,
            { configId: config.id },
            {
              jobId,
              repeat: { cron: schedule },
              removeOnComplete: true,
              removeOnFail: true,
            },
          );
          this.logger.log(`Scheduled feed processing for ${config.id} with cron ${schedule}`, { jobId });
        }
        const scheduledJobs = await this.feedQueue.getRepeatableJobs();
        this.logger.log(`Scheduled ${scheduledJobs.length} repeatable jobs`, {
          jobs: scheduledJobs.map(j => ({ id: j.id, name: j.name, cron: j.cron })),
        });
      } catch (error) {
        this.logger.error('Failed to schedule feed processing', { error: error.message, stack: error.stack });
      }
    }
  
    async getQueueStatus() {
      try {
        const [waiting, active, completed, failed] = await Promise.all([
          this.feedQueue.getWaiting(),
          this.feedQueue.getActive(),
          this.feedQueue.getCompleted(),
          this.feedQueue.getFailed(),
        ]);
        this.logger.log('Queue status', {
          waiting: waiting.length,
          active: active.length,
          completed: completed.length,
          failed: failed.length,
          waitingJobs: waiting.map(j => ({ id: j.id, name: j.name, data: j.data })),
          activeJobs: active.map(j => ({ id: j.id, name: j.name, data: j.data })),
          failedJobs: failed.map(j => ({ id: j.id, name: j.name, error: j.failedReason })),
        });
        return { waiting, active, completed, failed };
      } catch (error) {
        this.logger.error('Failed to get queue status', { error: error.message, stack: error.stack });
        return { waiting: [], active: [], completed: [], failed: [] };
      }
    }
  
    @Process('processAllFeeds')
  async handleProcessAllFeeds(job: Job): Promise<void> {
    const configs = await this.feedConfigService.getAllConfigs();
    if (!configs.length) return;

    await Promise.all(
      configs.map(config =>
        this.processFeed(config).catch(error => {
          this.logger.error(`Failed to process feed ${config.name}`, error);
        })
      )
    );
  }

  @Process({ name: 'processFeed:*' })
  async handleProcessFeed(job: Job<{ configId: string }>): Promise<void> {
    const { configId } = job.data;
    const config = await this.feedConfigService.getConfig(configId);
    if (!config) return;

    await this.processFeed(config).catch(error => {
      this.logger.error(`Failed to process feed ${config.name}`, error);
    });
  }

  private async processFeed(config: FeedProviderConfig): Promise<void> {
    const startTime = Date.now();
    this.logger.log(`Starting processing for feed: ${config.name}`);

    try {
      // Process the feed using the generator pattern
      const objectGenerator = this.fetchAndMapStixObjects(config);
      let successCount = 0;
      let duplicateCount = 0;
      let failedCount = 0;
      let processedCount = 0;

      for await (const stixObject of objectGenerator) {
        processedCount++;
        try {
          const result = await this.processStixObject(stixObject, config);
          result.isDuplicate ? duplicateCount++ : successCount++;
        } catch (error) {
          failedCount++;
          this.logger.error(`Failed to process STIX object`, {
            objectId: stixObject.id,
            error: error.message,
            stack: error.stack
          });
        }

        // Log progress periodically
        if (processedCount % 100 === 0) {
          this.logger.log(`Processing progress for ${config.name}: ${processedCount} objects processed`);
        }
      }

      this.logger.log(`Completed feed ${config.name}: ${successCount} stored, ${duplicateCount} duplicates, ${failedCount} failed in ${(Date.now() - startTime)/1000}s`);
    } catch (error) {
      this.logger.error(`Failed to process feed ${config.name}`, error);
    }
  }

  private getObjectLookupValue(obj: GenericStixObject): string {
    if (obj.indicator) return obj.indicator;
    if (obj.value) return obj.value;
    if (obj.name) return obj.name;
    if (obj.hashes && Object.values(obj.hashes).length > 0) {
      return Object.values(obj.hashes)[0];
    }
    if (obj.id) return obj.id;
    return '';
  }

  private async processStixObject(
    obj: GenericStixObject,
    config: FeedProviderConfig
  ): Promise<{ success: boolean; isDuplicate: boolean }> {
    const type = obj.type || 'observed-data';
    const lookupValue = this.getObjectLookupValue(obj);
  
    if (!['marking-definition', 'relationship', 'sighting'].includes(type)) {
      if (!lookupValue) {
        this.logger.warn(`Skipping invalid object: no valid lookup value`, { objectId: obj.id });
        return { success: false, isDuplicate: false };
      }
      const existing = await this.lookupService.findByValue(lookupValue, type);
      if (existing) {
        this.logger.debug(`Duplicate object found: ${type} (${lookupValue})`, { objectId: obj.id });
        return { success: true, isDuplicate: true };
      }
    }
  
    try {
      const stixResult = await this.transformToStixInput(obj, config);
      if (stixResult.input.extensions) {
        this.logger.debug(`Storing object with extensions`, {
          objectId: stixResult.input.id,
          type: stixResult.type,
          extensionCount: Object.keys(stixResult.input.extensions).length,
        });
      }
      const storedObject = await this.storeStixObject(stixResult.type, stixResult.input, obj);
      if (stixResult.relationships?.length > 0 && !['relationship', 'sighting'].includes(type)) {
        await this.createRelationships(storedObject, stixResult);
      }
      if (stixResult.additionalObjects?.length > 0) {
        await Promise.allSettled(
          stixResult.additionalObjects.map(async additionalObj => {
            try {
              const result = await this.processStixObject(additionalObj, config);
              if (result.success && !result.isDuplicate) {
                this.logger.debug(`Processed additional object ${additionalObj.id}`, {
                  type: additionalObj.type,
                  extensions: additionalObj.extensions ? Object.keys(additionalObj.extensions) : [],
                });
              }
            } catch (error) {
              this.logger.error(`Failed to process additional object ${additionalObj.id}`, {
                error: error.message,
                type: additionalObj.type,
              });
            }
          })
        );
      }
      return { success: true, isDuplicate: false };
    } catch (error) {
      this.logger.error(`Failed to process ${type}: ${lookupValue || obj.id}`, {
        error: error.message,
        stack: error.stack,
        objectId: obj.id,
      });
      return { success: false, isDuplicate: false };
    }
  }


  private mapObjectsWithConfig(object: any, config: FeedProviderConfig): GenericStixObject[] {
    try {
      const mapper = typeof config.objectMapper === 'string'
        ? objectMappers[config.objectMapper]
        : config.objectMapper;
  
      if (!mapper) {
        throw new Error(`No mapper configured for feed ${config.name}`);
      }
  
      const result = mapper(object);
  
      if (typeof result === 'object' && Symbol.iterator in result) {
        return [...result].filter(Boolean);
      } else if (Array.isArray(result)) {
        return result.filter(Boolean);
      } else if (result) {
        return [result];
      }
      return [];
    } catch (error) {
      this.logger.error(`Mapping failed for object`, {
        error: error.message,
        feed: config.name,
        rawData: JSON.stringify(object).substring(0, 100),
      });
      throw error;
    }
  }


  private async transformToStixInput(
    object: GenericStixObject & { _alreadyMapped?: boolean },
    config: FeedProviderConfig
  ): Promise<{
    type: StixType;
    input: any;
    relationships: any[];
    enriched: GenericStixObject;
    additionalObjects: GenericStixObject[];
  }> {
    // Skip mapping if already done in fetchAndMapStixObjects
    const mappedObjects = object._alreadyMapped 
      ? [object] 
      : this.mapObjectsWithConfig(object, config);
    
    if (!mappedObjects.length) {
      throw new Error(`No valid objects for ${object.type || 'unknown'}`);
    }
  
    const primaryObject = mappedObjects[0];
    let enrichedObject = { ...primaryObject };
    const nonEnrichableTypes = ['relationship', 'sighting', 'marking-definition'];
  
    // Enrich primary object only if it's eligible
    if (!nonEnrichableTypes.includes(primaryObject.type) && this.getEnrichmentServicesForType(primaryObject.type).length > 0) {
      try {
        enrichedObject = await this.enrichObject(primaryObject, config);
        this.logger.debug(`Enriched primary object ${primaryObject.id}`, {
          objectId: primaryObject.id,
          type: primaryObject.type,
          extensions: enrichedObject.extensions ? Object.keys(enrichedObject.extensions) : [],
        });
      } catch (error) {
        this.logger.warn(`Failed to enrich primary object ${primaryObject.id}`, {
          error: error.message,
          objectId: primaryObject.id,
          configId: config.id,
        });
      }
    } 
  
    // For already mapped objects, we don't expect additional objects or relationships
    const relationships = object._alreadyMapped 
      ? [] 
      : mappedObjects.slice(1).filter(obj => obj?.type === 'relationship');
    
    const additionalObjects = object._alreadyMapped 
      ? [] 
      : mappedObjects.slice(1).filter(obj => obj?.type !== 'relationship');
  
    // Enrich additional objects if they exist and are eligible
    const enrichedAdditionalObjects = await Promise.all(
      additionalObjects.map(async obj => {
        if (!nonEnrichableTypes.includes(obj.type) && this.getEnrichmentServicesForType(obj.type).length > 0) {
          try {
            const enrichedObj = await this.enrichObject(obj, config);
            this.logger.debug(`Enriched additional object ${obj.id}`, {
              objectId: obj.id,
              type: obj.type,
              extensions: enrichedObj.extensions ? Object.keys(enrichedObj.extensions) : [],
            });
            return enrichedObj;
          } catch (error) {
            this.logger.warn(`Failed to enrich additional object ${obj.id}`, {
              error: error.message,
              objectId: obj.id,
              type: obj.type,
            });
            return obj;
          }
        }
        this.logger.debug(`Skipped enrichment for additional object ${obj.id} (type: ${obj.type})`, {
          objectId: obj.id,
          type: obj.type,
        });
        return obj;
      })
    );
  
    // Remove internal flags before returning
    const { _alreadyMapped, _sourceConfig, ...cleanEnrichedObject } = enrichedObject;
  
    return {
      type: cleanEnrichedObject.type as StixType,
      input: cleanEnrichedObject,
      relationships,
      enriched: { ...cleanEnrichedObject, sourceConfigId: config.id },
      additionalObjects: enrichedAdditionalObjects,
    };
  }


  private async enrichObject(object: GenericStixObject, config: FeedProviderConfig): Promise<GenericStixObject> {
    const enrichmentServices = this.getEnrichmentServicesForType(object.type);
    if (!enrichmentServices.length) {
      this.logger.debug(`No enrichment services available for type ${object.type}`, {
        objectId: object.id,
        type: object.type,
      });
      return object;
    }
  
    const lookupValue = object.indicator || object.value || object.name || 
                       (object.hashes ? Object.values(object.hashes)[0] : null);
    if (!lookupValue) {
      return object;
    }
  
    try {
      const enrichmentData = await this.enrichmentService.enrichObject({
        indicator: lookupValue,
        type: object.type,
        sourceConfigId: config.id,
      }, {
        services: enrichmentServices,
      });
      return this.applyEnrichmentData(object, enrichmentData);
    } catch (error) {
      this.logger.warn(`Failed to enrich ${object.type} object`, {
        error: error.message,
        objectId: object.id,
        configId: config.id,
      });
      return object;
    }
  }



  private getEnrichmentServicesForType(type: StixType): EnrichmentServiceKey[] {
    // Explicitly skip enrichment for these types
    if (['relationship', 'sighting', 'marking-definition'].includes(type)) {
      return [];
    }
  
    const enrichmentMap: Record<string, EnrichmentServiceKey[]> = {
      'ipv4-addr': ['geo', 'abuseipdb', 'asn', 'virustotal', 'shodan'],
      'ipv6-addr': ['geo', 'abuseipdb', 'asn', 'virustotal'],
      'domain-name': ['whois', 'ssl', 'threatfox', 'virustotal'],
      'url': [ 'ssl', 'threatfox', 'virustotal'],
      'file': ['virustotal', 'misp', 'hybrid', 'threatcrowd'],
      'indicator': ['virustotal', 'threatfox', 'misp', ],
       'malware' :['virustotal', 'misp', 'threatfox'],
      'autonomous-system': ['asn'],
      'mutex': ['threatcrowd'],
      default: [],
    };
  
    return enrichmentMap[type] || enrichmentMap.default;
  }

  private applyEnrichmentData(
    object: GenericStixObject,
    enrichmentData: EnrichmentData
  ): GenericStixObject {
    if (Object.keys(enrichmentData).length === 0) {
      return object;
    }
  
    const extensions: Record<string, any> = object.extensions || {};
    Object.entries(enrichmentData).forEach(([serviceKey, data]) => {
      const extensionDef = ENRICHMENT_EXTENSIONS[serviceKey as EnrichmentServiceKey];
      if (!extensionDef) {
        this.logger.warn(`No extension definition found for enrichment service ${serviceKey}`, {
          objectId: object.id,
          type: object.type,
        });
        return;
      }
      extensions[extensionDef.id] = {
        extension_type: 'property-extension',
        ...data,
      };
      this.logger.debug(`Added ${serviceKey} enrichment as extension ${extensionDef.id} for object ${object.id}`, {
        objectId: object.id,
        type: object.type,
        serviceKey,
      });
    });
  
    return {
      ...object,
      extensions: Object.keys(extensions).length > 0 ? extensions : undefined,
    };
  }

  private async *fetchAndMapStixObjects(config: FeedProviderConfig, retryCount: number = 0): AsyncGenerator<GenericStixObject, void, unknown> {
    const apiKey = process.env[config.apiKeyEnv];
    if (!apiKey && config.apiKeyEnv) {
      throw new InternalServerErrorException(`${config.apiKeyEnv} not configured`);
    }
  
    // Initialize rate limiter
    if (!this.limiters.has(config.id)) {
      this.limiters.set(
        config.id,
        new Bottleneck({
          maxConcurrent: 1,
          minTime: config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY,
        }),
      );
    }
  
    const limiter = this.limiters.get(config.id)!;
    let page =1;
    const pageSize = config.data?.limit || config.params?.limit || 100;
    let hasMore = true;
  
    while (hasMore) {
      const pageStartTime = Date.now();
      let attempt = 0;
      const maxRetries = config.maxRetries || DEFAULT_MAX_RETRIES;
      let response: any = null;
  
      while (attempt <= maxRetries) {
        try {
          // Prepare request
          const headers = config.headers ? this.interpolateHeaders(config.headers, apiKey) : {};
          const params = {
            ...(config.params || {}),
            ...(config.pagination?.paramType === 'params' ? { 
              [config.pagination?.pageKey || 'page']: page, 
              limit: pageSize 
            } : {}),
          };
          const data = {
            ...(config.data || {}),
            ...(config.pagination?.paramType === 'data' ? { 
              [config.pagination?.pageKey || 'page']: page, 
              limit: pageSize 
            } : {}),
          };
  
          // Make API request through rate limiter
          response = await limiter.schedule(() =>
            axios({
              method: config.method || 'GET',
              url: config.apiUrl,
              headers,
              params: Object.keys(params).length > 0 ? params : undefined,
              data: Object.keys(data).length > 0 ? data : undefined,
              timeout: config.timeout || DEFAULT_TIMEOUT,
            }),
          );
  
          // Extract and map data
          let responseData = config.responsePath 
            ? this.getNestedProperty(response.data, config.responsePath) 
            : response.data;
  
          if (config.name === 'AlienVaultOTX' && responseData?.results) responseData = responseData.results;
          if (config.name === 'HybridAnalysis' && responseData?.data) responseData = responseData.data;
  
          if (!responseData) {
            throw new Error(`Empty response from ${config.name} API`);
          }
  
          const dataArray = Array.isArray(responseData) ? responseData : [responseData];
          let mappedCount = 0;
  
          for (const item of dataArray) {
          try {
            const mappedObjects = this.mapObjectsWithConfig(item, config);
            for (const stixObject of mappedObjects) {
              // Mark objects as already mapped
              const markedObject = {
                ...stixObject,
                _alreadyMapped: true,
                _sourceConfig: config.id
              };
              yield markedObject;
              mappedCount++;
            }
          } catch (error) {
            this.logger.warn(`Skipping item due to mapping error`, {
              error: error.message,
              feed: config.name,
            });
          }
        }
  
          // Log page fetch details
          const pageDuration = (Date.now() - pageStartTime) / 1000;
          this.logger.log(`Fetched page ${page} for ${config.name}: ${dataArray.length} items retrieved, ${mappedCount} STIX objects mapped in ${pageDuration}s`, {
            feed: config.name,
            page,
            itemsRetrieved: dataArray.length,
            objectsMapped: mappedCount,
          });
  
          // Determine pagination
          hasMore = this.shouldContinuePagination(config, response, dataArray, pageSize, page);
          if (config.pagination?.maxPages && page >= config.pagination.maxPages) {
            hasMore = false;
          }
          page++;
          break; // Break retry loop on success
        } catch (error) {
          if (error instanceof AxiosError) {
            const message = error.response?.data ? JSON.stringify(error.response.data) : error.message;
            if (error.response?.status === 403) {
              this.logger.error(`Invalid API credentials for ${config.name}`, { feed: config.name, error: message });
              throw new InternalServerErrorException(`Invalid ${config.name} API credentials`);
            }
  
            if (
              ([429, 503].includes(error.response?.status) || ['ECONNREFUSED', 'ETIMEDOUT'].includes(error.code || '')) &&
              attempt < maxRetries
            ) {
              const delay = Math.pow(2, attempt) * (config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY);
              this.logger.warn(`Retrying ${config.name} after ${delay}ms`, {
                feed: config.name,
                retry: attempt + 1,
                maxRetries,
                error: message,
              });
              await new Promise(resolve => setTimeout(resolve, delay));
              attempt++;
              continue;
            }
  
            this.logger.error(`API failed for ${config.name} after ${attempt + 1} attempts`, {
              feed: config.name,
              error: message,
            });
            throw new InternalServerErrorException(`${config.name} API failed after ${attempt + 1} attempts: ${message}`);
          } else {
            this.logger.error(`Unexpected error in fetchAndMapStixObjects for ${config.name}`, {
              error: error.message,
              stack: error.stack,
            });
            throw error;
          }
        }
      }
    }
  }

  private shouldContinuePagination(
    config: FeedProviderConfig,
    response: any,
    data: any[],
    pageSize: number,
    currentPage: number
  ): boolean {
    // If we got fewer items than requested, we're done
    if (data.length < pageSize) return false;

    // Check custom pagination indicators
    if (config.pagination?.hasNextKey) {
      return !!response.data[config.pagination.hasNextKey];
    }
    
    if (config.pagination?.totalCountKey) {
      const totalCount = response.data[config.pagination.totalCountKey];
      return currentPage * pageSize < totalCount;
    }

    // Default behavior - continue if we got a full page
    return data.length === pageSize;
  }



  private interpolateHeaders(headers: Record<string, string>, apiKey: string): Record<string, string> {
    return Object.fromEntries(
      Object.entries(headers).map(([key, value]) => [key, value.replace('${apiKey}', apiKey)])
    );
  }

  private getNestedProperty(obj: any, path: string): any {
    return path.split('.').reduce((acc, part) => acc?.[part], obj);
  }
  
   
  private validRelationships = new Map<string, Set<string>>([
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
  
  private readonly validTargets = new Map<string, Set<string>>([
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

  
  private async createRelationships(storedObject: { id: string }, result: any): Promise<void> {
    // Extract source and target types from ref IDs
    const getObjectType = (ref: string): string | null => {
      const type = ref.split('--')[0];
      return type || null;
    };
  
    // Validate relationship
    const isValidRelationship = (rel: any): boolean => {
      const sourceType = getObjectType(rel.source_ref);
      const targetType = getObjectType(rel.target_ref);
      const relationshipType = rel.relationship_type;
  
      if (!sourceType || !targetType || !relationshipType) {
        this.logger.warn(`Invalid relationship: missing source, target, or type`, {
          relationshipId: rel.id,
          source_ref: rel.source_ref,
          target_ref: rel.target_ref,
          relationship_type: relationshipType
        });
        return false;
      }
  
      // Check if source type supports the relationship type
      const allowedRelationships = this.validRelationships.get(sourceType);
      if (!allowedRelationships?.has(relationshipType)) {
        this.logger.warn(`Invalid relationship type for source type`, {
          relationshipId: rel.id,
          sourceType,
          relationshipType,
          allowedRelationships: Array.from(allowedRelationships || [])
        });
        return false;
      }
  
      // Check if target type is valid for the relationship type
      const allowedTargets = this.validTargets.get(relationshipType);
      if (!allowedTargets?.has(targetType)) {
        this.logger.warn(`Invalid target type for relationship`, {
          relationshipId: rel.id,
          relationshipType,
          targetType,
          allowedTargets: Array.from(allowedTargets || [])
        });
        return false;
      }
  
      return true;
    };
  
    // Filter valid relationships and update source_ref
    const relationships = result.relationships
      .filter((rel: any) => isValidRelationship(rel))
      .map((rel: any) => ({
        ...rel,
        source_ref: rel.source_ref === result.input.id ? storedObject.id : rel.source_ref,
        object_marking_refs: rel.object_marking_refs || [TLP_MARKINGS['white'].id],
      }));
  
    if (relationships.length) {
      this.logger.debug(`Creating ${relationships.length} valid relationships for ${result.input.type}`, {
        objectId: storedObject.id,
        relationships: relationships.map((r: any) => ({ id: r.id, type: r.relationship_type }))
      });
      const batchSize = 50;
      for (let i = 0; i < relationships.length; i += batchSize) {
        const batch = relationships.slice(i, i + batchSize);
        const results = await Promise.allSettled(batch.map((rel: any) => this.relationshipService.create(rel)));
        results.forEach((result, index) => {
          if (result.status === 'rejected') {
            this.logger.error(`Failed to create relationship ${batch[index].id}`, {
              error: result.reason.message,
              relationship: batch[index]
            });
          }
        });
      }
    } else if (result.relationships.length > 0) {
      this.logger.warn(`No valid relationships to create for ${result.input.type}`, {
        objectId: storedObject.id,
        invalidCount: result.relationships.length
      });
    }
  }
  private async storeStixObject(
    type: StixType,
    input: any,
    object: GenericStixObject
  ): Promise<{ id: string }> {
    const safeGetErrorInfo = (error: any) => ({
      message: error?.message || error?.body?.error || String(error),
      stack: error?.stack,
      code: error?.code,
      statusCode: error?.statusCode,
      details: error?.response?.data || error?.meta?.body
    });
  
    try {
      if (!this.logger) {
        console.error('Logger not initialized in FeedIngesterService');
      }
  
      const service = this.serviceFactory.get(type);
      if (!service) {
        const errorMsg = `No service found for STIX type ${type}`;
        this.logger?.error(errorMsg, { objectId: object.id });
        throw new InternalServerErrorException(errorMsg);
      }
  
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          this.logger?.log(`Attempt ${attempt}/3 to store ${type} ${object.id}`);
          const result = await service.create(input);
          
          if (!result?.id) {
            throw new Error('Service.create did not return valid ID');
          }
          
          return result;
        } catch (error) {
          const errorInfo = safeGetErrorInfo(error);
          const isDuplicate = this.isDuplicateError(error);
  
          // Handle duplicates immediately
          if (isDuplicate) {
            this.logger?.warn(`Duplicate ${type} detected`, { 
              objectId: object.id,
              existingId: object.id
            });
            return { id: object.id };
          }
  
          // Check if error is retryable (network issues or server errors)
          const isRetryable = this.isRetryableError(error);
          
          // Final attempt or non-retryable error
          if (attempt === 3 || !isRetryable) {
            this.logger?.error(`Permanent storage failure`, { 
              objectId: object.id,
              error: errorInfo.message,
              details: errorInfo.details,
              retryable: isRetryable,
              attempt
            });
            throw error;
          }
  
          // Calculate backoff only for retryable errors
          const delay = this.calculateBackoffDelay(attempt, 1000);
          this.logger?.warn(`Retrying in ${delay}ms`, {
            objectId: object.id,
            attempt,
            error: errorInfo.message,
            retryable: isRetryable
          });
          
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    } catch (error) {
      const errorInfo = safeGetErrorInfo(error);
      this.logger?.error(`Failed to store ${type} object`, {
        objectId: object.id,
        type,
        error: errorInfo.message,
        stack: errorInfo.stack,
        details: errorInfo.details
      });
  
      throw new InternalServerErrorException({
        message: `Failed to store STIX object ${object.id}`,
        details: errorInfo.message,
        type,
        objectId: object.id,
        errorCode: errorInfo.code,
        statusCode: errorInfo.statusCode
      });
    }
  
    // Fallback return (should never be reached)
    throw new InternalServerErrorException({
      message: `Unexpected error storing ${type} object`,
      objectId: object.id
    });
  }
  
  private isRetryableError(error: any): boolean {
    // Retry only on network errors or 5xx server errors
    const statusCode = error?.statusCode || error?.response?.status;
    return (
      [
        'ECONNRESET', 
        'ETIMEDOUT', 
        'ECONNREFUSED', 
        'ENOTFOUND'
      ].includes(error?.code) ||
      (statusCode >= 500 && statusCode < 600)
    );
  }
  private isDuplicateError(error: any): boolean {
    const errorMessage = String(error?.message || error).toLowerCase();
    return [
      'unique constraint',
      'duplicate key',
      'already exists',
      'conflict',
      'duplicate document'
    ].some(term => errorMessage.includes(term.toLowerCase()));
  }


  private calculateBackoffDelay(attempt: number, baseDelayMs: number): number {
  const cappedAttempt = Math.min(attempt, 5);
  return Math.floor(baseDelayMs * (2 ** cappedAttempt) + Math.random() * 500);
}
    }