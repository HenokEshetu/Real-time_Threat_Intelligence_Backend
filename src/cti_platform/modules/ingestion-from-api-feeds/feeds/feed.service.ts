import { LookupService } from '../../../core/utils/lookup.service';
import { CommonProperties, ExternalReference, STIXPattern } from '../../../core/types/common-data-types';
import { BundleService } from '../../stix-objects/bundle/bundle.service';
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
import {CreateArtifactInput} from '../../stix-objects/cyber-observables/artifact/artifact.input';
import {CreateAutonomousSystemInput} from '../../stix-objects/cyber-observables/autonomous-system/autonomous-system.input'; 
import {CreateDirectoryInput} from '../../stix-objects/cyber-observables/directory/directory.input';
import {CreateDomainNameInput} from '../../stix-objects/cyber-observables/domain-name/domain-name.input';
import {CreateEmailAddressInput} from '../../stix-objects/cyber-observables/email-address/email-address.input';
import {CreateEmailMessageInput} from '../../stix-objects/cyber-observables/email-message/email-message.input';
import {CreateFileInput} from '../../stix-objects/cyber-observables/file/file.input';
import {CreateIPv4AddressInput} from '../../stix-objects/cyber-observables/ipv4-address/ipv4-address.input';
import {CreateIPv6AddressInput} from '../../stix-objects/cyber-observables/ipv6-address/ipv6-address.input';
import {CreateMACAddressInput} from '../../stix-objects/cyber-observables/mac-address/mac-address.input';
import {CreateMutexInput} from '../../stix-objects/cyber-observables/mutex/mutex.input';
import {CreateNetworkTrafficInput} from '../../stix-objects/cyber-observables/network-traffic/network-traffic.input';
import {CreateProcessInput} from '../../stix-objects/cyber-observables/process/process.input';
import {CreateSoftwareInput} from '../../stix-objects/cyber-observables/software/software.input';
import {CreateUrlInput} from '../../stix-objects/cyber-observables/url/url.input';
import {CreateUserAccountInput} from '../../stix-objects/cyber-observables/user-account/user-account.input';
import {CreateWindowsRegistryKeyInput} from '../../stix-objects/cyber-observables/windows-registry-key/windows-registry-key.input';
import {CreateAttackPatternInput} from '../../stix-objects/domain-objects/attack-pattern/attack-pattern.input';
import {CreateCampaignInput} from '../../stix-objects/domain-objects/campaign/campaign.input';
import {CreateCourseOfActionInput} from '../../stix-objects/domain-objects/course-of-action/course-of-action.input';
import {CreateGroupingInput} from '../../stix-objects/domain-objects/grouping/grouping.input';
import {CreateIdentityInput} from '../../stix-objects/domain-objects/identity/identity.input';
import {CreateIncidentInput} from '../../stix-objects/domain-objects/incident/incident.input';
import {CreateIndicatorInput} from '../../stix-objects/domain-objects/indicator/indicator.input';
import {CreateInfrastructureInput} from '../../stix-objects/domain-objects/infrastructure/infrastructure.input';
import {CreateIntrusionSetInput} from '../../stix-objects/domain-objects/intrusion-set/intrusion-set.input';
import {CreateLocationInput} from '../../stix-objects/domain-objects/location/location.input';
import {CreateMalwareInput} from '../../stix-objects/domain-objects/malware/malware.input';
import {CreateMalwareAnalysisInput} from '../../stix-objects/domain-objects/malware-analysis/malware-analysis.input';
import {CreateNoteInput} from '../../stix-objects/domain-objects/note/note.input';
import {CreateObservedDataInput} from '../../stix-objects/domain-objects/observed-data/observed-data.input';
import {CreateOpinionInput} from '../../stix-objects/domain-objects/opinion/opinion.input';
import {CreateReportInput} from '../../stix-objects/domain-objects/report/report.input';
import {CreateThreatActorInput} from '../../stix-objects/domain-objects/threat-actor/threat-actor.input';
import {CreateToolInput} from '../../stix-objects/domain-objects/tool/tool.input';
import {CreateVulnerabilityInput} from '../../stix-objects/domain-objects/vulnerability/vulnerability.input';
import {CreateSightingInput} from '../../stix-objects/sighting/sighting.input';
import { CreateRelationshipInput } from '../../stix-objects/relationships/relationship.input';
import { CreateBundleInput } from '../../stix-objects/bundle/bundle.input';
import { CreateX509CertificateInput } from '../../stix-objects/cyber-observables/x.509-certificate/x509-certificate.input';


import { Injectable, InternalServerErrorException, OnModuleInit, Logger } from '@nestjs/common';
import { InjectQueue, Process, Processor } from '@nestjs/bull';
import { Queue, Job } from 'bull';
import axios, { AxiosError } from 'axios';
import Bottleneck from 'bottleneck';
import { v4 as uuidv4 } from 'uuid';
import { FeedProviderConfig, GenericStixObject, StixType } from './feed.types';
import { FeedUtils } from './feed.utils';
import { FeedConfigService } from './feed-config.service';

import {
  DEFAULT_BATCH_SIZE,
  DEFAULT_TIMEOUT,
  DEFAULT_RATE_LIMIT_DELAY,
  DEFAULT_MAX_RETRIES,
  TLP_MARKINGS,
  STIX_SPEC_VERSION,
} from './feed.constants';


// Define a generic StixService interface
interface StixService<T> {
  create(input: T): Promise<{ id: string; [key: string]: any }>;
}

// Union of all Create*Input types
type StixCreateInput =
  | CreateArtifactInput
  | CreateAutonomousSystemInput
  | CreateDirectoryInput
  | CreateDomainNameInput
  | CreateEmailAddressInput
  | CreateEmailMessageInput
  | CreateFileInput
  | CreateIPv4AddressInput
  | CreateIPv6AddressInput
  | CreateMACAddressInput
  | CreateMutexInput
  | CreateNetworkTrafficInput
  | CreateProcessInput
  | CreateSoftwareInput
  | CreateUrlInput
  | CreateUserAccountInput
  | CreateWindowsRegistryKeyInput
  | CreateX509CertificateInput
  | CreateAttackPatternInput
  | CreateCampaignInput
  | CreateCourseOfActionInput
  | CreateGroupingInput
  | CreateIdentityInput
  | CreateIncidentInput
  | CreateIndicatorInput
  | CreateInfrastructureInput
  | CreateIntrusionSetInput
  | CreateLocationInput
  | CreateMalwareInput
  | CreateMalwareAnalysisInput
  | CreateNoteInput
  | CreateObservedDataInput
  | CreateOpinionInput
  | CreateReportInput
  | CreateThreatActorInput
  | CreateToolInput
  | CreateVulnerabilityInput
  | CreateSightingInput
  | CreateRelationshipInput
  | CreateBundleInput;

interface EnrichmentResult {
  type: StixType;
  input: StixCreateInput;
  relationships: CreateRelationshipInput[];
  enriched: GenericStixObject;
}

@Processor('feedQueue')
@Injectable()
export class FeedIngesterService implements OnModuleInit {
  private readonly logger = new Logger(FeedIngesterService.name);
  private readonly defaultCreatedByRef: string;
  private readonly concurrency: number = parseInt(process.env.FEED_CONCURRENCY || '10', 10);
  private readonly defaultSchedule: string = process.env.FEED_SCHEDULE || '*/2 * * * *'; // Default: every 2 minutes
  private readonly defaultTimeout: number = parseInt(process.env.FEED_TIMEOUT || `${DEFAULT_TIMEOUT}`, 10);
  private readonly limiters: Map<string, Bottleneck> = new Map(); // Store limiters per feed

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
  ]);

  constructor(
    private readonly bundleService: BundleService,
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
    private readonly lookupService: LookupService,
    @InjectQueue('feedQueue') private readonly feedQueue: Queue,
    private readonly enrichmentService: EnrichmentService,
    private readonly feedConfigService: FeedConfigService,
  ) {
    this.defaultCreatedByRef = `identity--${process.env.IDENTITY_ID || uuidv4()}`;
  }

  async onModuleInit() {
    await this.initializeLimiters();
    await this.scheduleFeedProcessing();
    this.logger.log('Feed Ingester Service initialized');
  }

  private async initializeLimiters() {
    try {
      const configs = await this.feedConfigService.getAllConfigs();
      if (configs.length === 0) {
        this.logger.warn('No feed configurations found during limiter initialization');
        return;
      }
      for (const config of configs) {
        this.limiters.set(
          config.id,
          new Bottleneck({
            maxConcurrent: 1,
            minTime: config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY, // Default to 1000ms
          }),
        );
        this.logger.debug(`Initialized rate limiter for feed ${config.id} with rateLimitDelay ${config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY}ms`);
      }
      this.logger.log(`Initialized ${this.limiters.size} rate limiters`);
    } catch (error) {
      this.logger.error(`Failed to initialize rate limiters: ${error instanceof Error ? error.message : error}`);
      throw new InternalServerErrorException('Failed to initialize rate limiters');
    }
  }

  private async scheduleFeedProcessing(): Promise<void> {
    try {
      await this.feedQueue.empty();
      const repeatableJobs = await this.feedQueue.getRepeatableJobs();
      for (const job of repeatableJobs) {
        await this.feedQueue.removeRepeatableByKey(job.key);
      }

      const configs = await this.feedConfigService.getAllConfigs();
      if (configs.length === 0) {
        this.logger.warn('No feed configurations found');
        return;
      }

      const schedule = configs[0].schedule || this.defaultSchedule;
      await this.feedQueue.add(
        'processAllFeeds',
        {},
        { repeat: { cron: schedule }, jobId: `all-feeds-${uuidv4()}` },
      );
      this.logger.log(`Scheduled feed processing with cron ${schedule}`);
    } catch (error) {
      this.logger.error(`Failed to schedule feed processing: ${error instanceof Error ? error.message : error}`);
      throw new InternalServerErrorException('Failed to initialize feed scheduler');
    }
  }

  @Process('processAllFeeds')
  async handleProcessAllFeeds(job: Job): Promise<void> {
    this.logger.log(`Starting job ${job.id} to process all feeds`);
    try {
      const configs = await this.feedConfigService.getAllConfigs();
      if (configs.length === 0) {
        this.logger.warn(`No feed configurations for job ${job.id}`);
        return;
      }

      await Promise.all(
        configs.map(config =>
          this.processFeed(config).catch(error => {
            this.logger.error(`Failed to process feed ${config.name}: ${error instanceof Error ? error.message : error}`);
          }),
        ),
      );
      this.logger.log(`Job ${job.id} completed`);
    } catch (error) {
      this.logger.error(`Job ${job.id} failed: ${error instanceof Error ? error.message : error}`);
      throw new InternalServerErrorException(`Feed processing failed: ${error instanceof Error ? error.message : error}`);
    }
  }

  private async processFeed(config: FeedProviderConfig): Promise<void> {
    const startTime = Date.now();
    this.logger.log(`Processing feed ${config.name}`);
    let indicators: GenericStixObject[] = [];

    try {
      indicators = await this.fetchStixObjects(config, 0);
      if (!indicators.length) {
        this.logger.warn(`No indicators fetched from ${config.name}`);
        return;
      }
    } catch (error) {
      this.logger.error(`Failed to fetch indicators from ${config.name}: ${error instanceof Error ? error.message : error}`);
      throw error;
    }

    let failedCount = 0;
    const batchSize = config.batchSize || DEFAULT_BATCH_SIZE;
    for (let i = 0; i < indicators.length; i += batchSize) {
      const batch = indicators.slice(i, i + batchSize);
      const results = await Promise.allSettled(
        batch.map(indicator =>
          this.processStixObject(indicator, config).catch(err => {
            this.logger.error(`Error processing ${indicator.indicator}: ${err instanceof Error ? err.message : err}`);
            return Promise.reject(err);
          }),
        ),
      );
      failedCount += results.filter(r => r.status === 'rejected').length;
      await new Promise(resolve => setTimeout(resolve, config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY));
    }

    const elapsedSeconds = (Date.now() - startTime) / 1000;
    this.logger.log(
      `Completed ${config.name} with ${indicators.length - failedCount}/${indicators.length} objects processed in ${elapsedSeconds}s`,
    );
  }

  private async processStixObject(obj: GenericStixObject, config: FeedProviderConfig): Promise<boolean> {
    const loggerContext = `Feed ${config.name}, ID ${obj.id || 'unknown'}`;
    this.logger.debug(`Processing indicator: ${JSON.stringify(obj, null, 2)} [${loggerContext}]`);

    // Validate indicator
    if (!obj || (!obj.indicator && !obj.value && !obj.name && !obj.hashes)) {
      this.logger.warn(`Skipping invalid indicator: ${JSON.stringify(obj, null, 2)} [${loggerContext}]`);
      return false;
    }

    const stixType = FeedUtils.identifyStixType(obj);

    const lookupValue = obj.indicator || obj.value || obj.name || (obj.hashes ? Object.values(obj.hashes)[0] : undefined);
    if (!lookupValue) {
      this.logger.warn(`No valid lookup value for indicator: ${JSON.stringify(obj, null, 2)} [${loggerContext}]`);
      return false;
    }

    if (await this.lookupService.findByValue(lookupValue, stixType)) {
      this.logger.debug(`Skipping duplicate ${stixType}: ${lookupValue} [${loggerContext}]`);
      return true;
    }

    const normalizedObj = {
      ...obj,
      id: obj.id || uuidv4(),
      type: stixType,
      sourceConfigId: config.id,
    };

    const enrichedResult = await this.enrichmentService.enrichIndicator(normalizedObj);
    const enrichedObj = this.adaptToGenericIndicator(enrichedResult);

    const stixResult = await this.transformToStixInput(enrichedObj, config);
    const storedObject = await this.storeStixObject(stixResult.type, stixResult.input, enrichedObj);

    const relationships = this.buildInitialRelationships(enrichedObj, storedObject.id);
    if (relationships.length > 0) {
      await Promise.all(
        relationships.map(rel =>
          this.relationshipService.create(rel).catch(err => {
            this.logger.warn(`Failed to create relationship for ${storedObject.id}: ${err instanceof Error ? err.message : err} [${loggerContext}]`);
          }),
        ),
      );
    }

    this.logger.log(`Successfully processed ${stixType}: ${storedObject.id} [${loggerContext}]`);
    return true;
  }

  private adaptToGenericIndicator(enrichedResult: any): GenericStixObject {
    const { enrichment, ...baseIndicator } = enrichedResult;

    const allowedEnrichmentSources = new Set([
      'geo',
      'whois',
      'virustotal',
      'abuseipdb',
      'shodan',
      'threatfox',
      'dns',
      'ssl',
      'asn',
      'hybrid',
      'threatcrowd',
      'misp',
      'ipinfo',
    ]);

    const adaptedEnrichment = enrichment
      ? Object.fromEntries(Object.entries(enrichment).filter(([key]) => allowedEnrichmentSources.has(key)))
      : undefined;

    return {
      ...baseIndicator,
      enrichment: adaptedEnrichment,
    };
  }

  private async transformToStixInput(indicator: GenericStixObject, config: FeedProviderConfig): Promise<EnrichmentResult> {
    const type = FeedUtils.identifyStixType(indicator);
    const commonProps = this.createCommonProperties(indicator, config);
    const pattern = FeedUtils.createStixPattern(indicator);

    const externalReferences = this.buildExternalReferences(indicator, config);

    const baseInput = {
      ...commonProps,
      type,
      external_references: externalReferences.length > 0 ? externalReferences : undefined,
      enrichment: indicator.enrichment,
    };

    const typeSpecificInput = this.createTypeSpecificInput(type, baseInput, indicator, pattern);

    const relationships = this.buildInitialRelationships(indicator, typeSpecificInput.id);

    return {
      type,
      input: typeSpecificInput,
      relationships,
      enriched: indicator,
    };
  }

  private createCommonProperties(
    indicator: GenericStixObject,
    config: FeedProviderConfig,
  ): Partial<CommonProperties> & { type: string } {
    const now = new Date().toISOString();
    const tlpLevel = FeedUtils.determineTLPLevel(indicator);
    return {
      type: 'indicator',
      spec_version: STIX_SPEC_VERSION,
      id: `${indicator.type || 'indicator'}--${uuidv4()}`,
      created_by_ref: this.defaultCreatedByRef,
      created: indicator.created || now,
      modified: indicator.modified || now,
      revoked: false,
      labels: [config.id, ...(indicator.labels || [])],
      confidence: FeedUtils.calculateConfidence(indicator),
      external_references: this.buildExternalReferences(indicator, config),
      object_marking_refs: [TLP_MARKINGS[tlpLevel].id],
      extensions: {},
    };
  }

  private buildExternalReferences(indicator: GenericStixObject, config: FeedProviderConfig): ExternalReference[] {
    const refs: ExternalReference[] = [];

    refs.push({
      id: uuidv4(),
      source_name: config.name,
      external_id: indicator.id,
      url: indicator.id && config.apiUrl ? `${config.apiUrl}/${indicator.id}` : undefined,
      description: `Original ${config.name} indicator`,
    });

    if (Array.isArray(indicator.references) && indicator.references.length) {
      refs.push(
        ...indicator.references.map(ref => ({
          id: uuidv4(),
          source_name: 'External Reference',
          url: ref,
        })),
      );
    }

    const enrichmentReferenceMap: Record<
      string,
      {
        sourceName: string;
        dataKey?: string;
        urlFn: (indicator: GenericStixObject, data: any) => string | undefined;
        descriptionFn: (data: any) => string;
        externalIdFn?: (indicator: GenericStixObject) => string;
      }
    > = {
      virustotal: {
        sourceName: 'VirusTotal',
        dataKey: 'data.attributes.last_analysis_stats',
        urlFn: (indicator) =>
          `https://www.virustotal.com/gui/${indicator.type.includes('file') ? 'file' : 'ip-address'}/${indicator.indicator}`,
        descriptionFn: (data) => {
          const stats = data?.attributes?.last_analysis_stats ?? { malicious: 0, undetected: 0, total: 0 };
          const total = stats.total ?? stats.malicious + (stats.undetected ?? 0);
          return `VirusTotal detection: ${stats.malicious}/${total}`;
        },
        externalIdFn: (indicator) => indicator.indicator,
      },
      abuseipdb: {
        sourceName: 'AbuseIPDB',
        dataKey: 'data.totalReports',
        urlFn: (indicator) => `https://www.abuseipdb.com/check/${indicator.indicator}`,
        descriptionFn: (data) =>
          `AbuseIPDB reports: ${data.totalReports ?? 0}, Score: ${data.abuseConfidenceScore ?? 'N/A'}`,
        externalIdFn: (indicator) => indicator.indicator,
      },
      threatfox: {
        sourceName: 'ThreatFox',
        dataKey: 'data',
        urlFn: (indicator) => `https://threatfox.abuse.ch/browse.php?search=${indicator.indicator}`,
        descriptionFn: (data) => `ThreatFox IOCs: ${data?.length ?? 0}`,
        externalIdFn: (indicator) => indicator.indicator,
      },
      hybrid: {
        sourceName: 'Hybrid Analysis',
        dataKey: 'summary',
        urlFn: (indicator, data) =>
          `https://www.hybrid-analysis.com/sample/${data?.hashes?.sha256 || indicator.indicator}`,
        descriptionFn: (data) =>
          `Hybrid Analysis: Threat Score ${data?.summary?.threat_score ?? 'N/A'}, Verdict: ${data?.summary?.verdict ?? 'N/A'}`,
        externalIdFn: (indicator) => indicator.indicator,
      },
      threatcrowd: {
        sourceName: 'ThreatCrowd',
        dataKey: 'hashes',
        urlFn: (indicator) => `https://www.threatcrowd.org/search.php?search=${indicator.indicator}`,
        descriptionFn: (data) => `ThreatCrowd: ${data?.hashes?.length ?? 0} related hashes`,
        externalIdFn: (indicator) => indicator.indicator,
      },
      misp: {
        sourceName: 'MISP',
        dataKey: 'events',
        urlFn: () => undefined,
        descriptionFn: (data) => `MISP: ${data?.events?.length ?? 0} related events`,
        externalIdFn: (indicator) => indicator.indicator,
      },
    };

    if (indicator.enrichment) {
      Object.entries(indicator.enrichment).forEach(([source, enrichmentData]) => {
        const config = enrichmentReferenceMap[source];
        if (!config || !enrichmentData) return;

        let data = enrichmentData;
        if (config.dataKey) {
          const keys = config.dataKey.split('.');
          data = keys.reduce((obj, key) => obj?.[key], enrichmentData);
          if (!data || (Array.isArray(data) && !data.length)) return;
        }

        refs.push({
          id: uuidv4(),
          source_name: config.sourceName,
          external_id: config.externalIdFn ? config.externalIdFn(indicator) : undefined,
          url: config.urlFn(indicator, enrichmentData),
          description: config.descriptionFn(enrichmentData),
        });
      });
    }

    return refs;
  }

  private createTypeSpecificInput(
    type: StixType,
    baseInput: Partial<CommonProperties> & { type: string },
    indicator: GenericStixObject,
    pattern: STIXPattern,
  ): StixCreateInput {
    const extensions: Record<string, any> = {};
    if (indicator.enrichment) {
      Object.entries(indicator.enrichment).forEach(([key, value]) => {
        if (value) extensions[`x-feed-${key}`] = value;
      });
    }

    switch (type) {
      case 'artifact':
        return { ...baseInput, type, content: indicator.indicator, extensions } as CreateArtifactInput;
      case 'autonomous-system':
        return { ...baseInput, type, number: parseInt(indicator.indicator.replace('AS', ''), 10) || 0, extensions } as CreateAutonomousSystemInput;
      case 'directory':
        return { ...baseInput, type, path: indicator.indicator, extensions } as CreateDirectoryInput;
      case 'domain-name':
        return {
          ...baseInput,
          type,
          value: indicator.indicator,
          resolves_to_refs: indicator.enrichment?.dns?.Answer?.map(a => `${a.type === 'A' ? 'ipv4-addr' : 'ipv6-addr'}--${uuidv4()}`),
          extensions,
        } as CreateDomainNameInput;
      case 'email-addr':
        return { ...baseInput, type, value: indicator.indicator, extensions } as CreateEmailAddressInput;
      case 'email-message':
        return { ...baseInput, type, subject: indicator.indicator, extensions } as CreateEmailMessageInput;
      case 'file':
        const hashType = indicator.type.includes('md5')
          ? 'MD5'
          : indicator.type.includes('sha1')
            ? 'SHA-1'
            : indicator.type.includes('sha256')
              ? 'SHA-256'
              : indicator.type.includes('sha512')
                ? 'SHA-512'
                : 'SHA-256';
        return {
          ...baseInput,
          type,
          hashes: {
            [hashType]: indicator.indicator,
            ...(indicator.enrichment?.hybrid?.hashes || {}),
          },
          name: indicator.enrichment?.virustotal?.data?.attributes?.names?.[0],
          extensions,
        } as CreateFileInput;
      case 'ipv4-addr':
        return { ...baseInput, type, value: indicator.indicator, extensions } as CreateIPv4AddressInput;
      case 'ipv6-addr':
        return { ...baseInput, type, value: indicator.indicator, extensions } as CreateIPv6AddressInput;
      case 'mac-address':
        return { ...baseInput, type, value: indicator.indicator, extensions } as CreateMACAddressInput;
      case 'mutex':
        return { ...baseInput, type, name: indicator.indicator, extensions } as CreateMutexInput;
      case 'network-traffic':
        return {
          ...baseInput,
          type,
          dst_ref: indicator.enrichment?.dns?.Answer?.[0]?.data
            ? `${indicator.enrichment.dns.Answer[0].type === 'A' ? 'ipv4-addr' : 'ipv6-addr'}--${uuidv4()}`
            : undefined,
          extensions,
        } as CreateNetworkTrafficInput;
      case 'process':
        return { ...baseInput, type, pid: parseInt(indicator.indicator, 10) || undefined, extensions } as CreateProcessInput;
      case 'software':
        return { ...baseInput, type, name: indicator.indicator, extensions } as CreateSoftwareInput;
      case 'url':
        return { ...baseInput, type, value: indicator.indicator, defanged: true, extensions } as CreateUrlInput;
      case 'user-account':
        return { ...baseInput, type, account_login: indicator.indicator, extensions } as CreateUserAccountInput;
      case 'windows-registry-key':
        return { ...baseInput, type, key: indicator.indicator, extensions } as CreateWindowsRegistryKeyInput;
      case 'x509-certificate':
        return { ...baseInput, type, serial_number: indicator.indicator, extensions } as CreateX509CertificateInput;
      case 'indicator':
        return {
          ...baseInput,
          type,
          name: `Indicator: ${indicator.indicator}`,
          description: FeedUtils.buildDescription(indicator),
          pattern: pattern.pattern,
          pattern_type: pattern.pattern_type,
          pattern_version: pattern.pattern_version,
          valid_from: new Date(pattern.valid_from),
          valid_until: pattern.valid_until ? new Date(pattern.valid_until) : undefined,
          extensions,
        } as CreateIndicatorInput;
      case 'malware':
        return {
          ...baseInput,
          type,
          name: indicator.indicator,
          malware_types: indicator.malwareTypes || [],
          is_family: indicator.malwareTypes?.includes('family') || false,
          capabilities: indicator.malwareCapabilities || [],
          implementation_languages: FeedUtils.inferImplementationLanguages(indicator.description),
          architecture_execution_envs: FeedUtils.inferArchitectures(indicator.description),
          extensions,
        } as CreateMalwareInput;
      case 'threat-actor':
        return {
          ...baseInput,
          type,
          name: indicator.indicator,
          threat_actor_types: indicator.threatActorTypes || [],
          aliases: indicator.aliases || [],
          roles: indicator.roles || [],
          sophistication: indicator.actorSophistication || 'unknown',
          resource_level: indicator.resourceLevel || 'unknown',
          primary_motivation: FeedUtils.inferPrimaryMotivation(indicator.description) || 'unknown',
          secondary_motivations: FeedUtils.inferSecondaryMotivations(indicator.description),
          extensions,
        } as CreateThreatActorInput;
      default:
        return {
          ...baseInput,
          type: 'observed-data',
          first_observed: new Date(indicator.created || baseInput.created),
          last_observed: new Date(indicator.modified || baseInput.modified),
          number_observed: 1,
          object_refs: [`${type}--${uuidv4()}`],
          extensions,
        } as CreateObservedDataInput;
    }
  }

  private buildInitialRelationships(indicator: GenericStixObject, sourceId: string): CreateRelationshipInput[] {
    const relationships: CreateRelationshipInput[] = [];
    const now = new Date().toISOString();

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
      ['file', new Set(['drops', 'delivers', 'related-to'])],
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
      ['communicates-with', new Set(['infrastructure', 'ipv4-addr', 'ipv6-addr'])],
      ['related-to', new Set(['file', 'indicator', 'malware'])],
      ['resolves-to', new Set(['ipv4-addr', 'ipv6-addr'])],
    ]);

    const addRelationships = (
      refs: any[] | undefined,
      relationshipType: string,
      targetType: string,
      descriptionFn: (item: any) => string,
    ) => {
      if (!Array.isArray(refs) || !refs.length) return;

      const sourceType = sourceId.split('--')[0];
      if (!validRelationships.get(sourceType)?.has(relationshipType)) {
        this.logger.warn(`Skipping invalid relationship: ${sourceType} cannot have '${relationshipType}'`);
        return;
      }
      if (!validTargets.get(relationshipType)?.has(targetType)) {
        this.logger.warn(`Skipping invalid target: '${relationshipType}' cannot target ${targetType}`);
        return;
      }

      relationships.push(
        ...refs.map(item => ({
          id: `relationship--${uuidv4()}`,
          type: 'relationship',
          spec_version: STIX_SPEC_VERSION,
          created: now,
          modified: now,
          source_ref: sourceId,
          target_ref: `${targetType}--${uuidv4()}`,
          relationship_type: relationshipType,
          description: descriptionFn(item),
        } as CreateRelationshipInput)),
      );
    };

    addRelationships(indicator.relatedIndicators, 'related-to', 'indicator', () => 'Related indicator');
    addRelationships(indicator.relatedFiles, 'related-to', 'file', () => 'Related file');
    addRelationships(indicator.indicatorRelationships, 'based-on', 'indicator', () => 'Based on indicator');
    addRelationships(indicator.relatedThreatActors, 'attributed-to', 'threat-actor', () => 'Attributed to threat actor');

    const enrichmentRelationshipMap: Record<
      string,
      {
        relationshipType: string;
        defaultTargetType: string;
        dataKey?: string;
        targetTypeFn?: (item: any) => string;
        descriptionFn: (item: any) => string;
      }
    > = {
      threatfox: {
        relationshipType: 'indicates',
        defaultTargetType: 'malware',
        dataKey: 'data',
        descriptionFn: (item) => `Linked to ThreatFox malware: ${item.malware || 'Unknown'}`,
      },
      dns: {
        relationshipType: 'resolves-to',
        defaultTargetType: 'ipv4-addr',
        dataKey: 'Answer',
        targetTypeFn: (item) => (item.type === 'A' ? 'ipv4-addr' : 'ipv6-addr'),
        descriptionFn: (item) => `Resolves to ${item.data} (${item.type})`,
      },
      hybrid: {
        relationshipType: 'related-to',
        defaultTargetType: 'file',
        dataKey: 'hashes',
        descriptionFn: (item) => `Linked to Hybrid Analysis hash: ${item[0].toUpperCase()} - ${item[1]}`,
      },
      threatcrowd: {
        relationshipType: 'communicates-with',
        defaultTargetType: 'ipv4-addr',
        dataKey: 'ips',
        targetTypeFn: (item) => (item.includes(':') ? 'ipv6-addr' : 'ipv4-addr'),
        descriptionFn: (item) => `ThreatCrowd related IP: ${item}`,
      },
      misp: {
        relationshipType: 'related-to',
        defaultTargetType: 'malware',
        dataKey: 'events',
        descriptionFn: (item) => `Linked to MISP event: ${item.Event?.info || 'Unknown'}`,
      },
    };

    if (indicator.enrichment) {
      Object.entries(indicator.enrichment).forEach(([source, enrichmentData]) => {
        const config = enrichmentRelationshipMap[source];
        if (!config || !enrichmentData) return;

        let data = config.dataKey ? (enrichmentData as any)[config.dataKey] : enrichmentData;
        if (source === 'hybrid' && data) {
          data = Object.entries(data);
        }

        if (Array.isArray(data) && data.length > 0) {
          data.forEach(item => {
            const targetType = config.targetTypeFn ? config.targetTypeFn(item) : config.defaultTargetType;
            addRelationships([item], config.relationshipType, targetType, config.descriptionFn);
          });
        }
      });
    }

    return relationships;
  }

  private async fetchStixObjects(config: FeedProviderConfig, retryCount: number): Promise<GenericStixObject[]> {
    const apiKey = process.env[config.apiKeyEnv];
    if (!apiKey) {
      throw new InternalServerErrorException(`${config.apiKeyEnv} not configured`);
    }

    // Ensure a limiter exists, create one if missing
    if (!this.limiters.has(config.id)) {
      this.logger.warn(`No rate limiter found for ${config.id}, creating one with rateLimitDelay ${config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY}ms`);
      this.limiters.set(
        config.id,
        new Bottleneck({
          maxConcurrent: 1,
          minTime: config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY,
        }),
      );
    }

    const limiter = this.limiters.get(config.id)!;

    try {
      const headers = config.headers ? this.interpolateHeaders(config.headers, apiKey) : {};

      const response = await limiter.schedule(() =>
        axios({
          method: config.method || 'GET',
          url: config.apiUrl,
          headers,
          params: config.params,
          data: config.data,
          timeout: config.timeout || DEFAULT_TIMEOUT,
        }),
      );

      const data = config.responsePath ? this.getNestedProperty(response.data, config.responsePath) : response.data;
      if (!Array.isArray(data)) {
        throw new Error(`Invalid response format from ${config.name} API`);
      }

      const stixObjects = data
        .map(raw => {
          const mapped = config.indicatorMapper(raw);
          if (!mapped.type || !FeedUtils.isValidStixType(mapped.type)) {
            this.logger.warn(`Skipping invalid STIX type: ${JSON.stringify(mapped)}`);
            return null;
          }
          if (!this.isValidStixObject(mapped)) {
            this.logger.warn(`Skipping invalid STIX object: ${JSON.stringify(mapped)}`);
            return null;
          }
          return { ...mapped, sourceConfigId: config.id };
        })
        .filter(obj => obj !== null) as GenericStixObject[];

      this.logger.log(`Fetched ${stixObjects.length}/${data.length} valid objects from ${config.name}`);
      return stixObjects;
    } catch (error) {
      return this.handleFetchError(error as AxiosError, config, retryCount);
    }
  }

  private isValidStixObject(obj: GenericStixObject): boolean {
    switch (obj.type) {
      case 'file':
        return !!(obj.hashes && Object.keys(obj.hashes).length > 0) || !!obj.value;
      case 'url':
      case 'domain-name':
      case 'ipv4-addr':
      case 'ipv6-addr':
      case 'email-addr':
        return !!obj.value;
      case 'malware':
      case 'threat-actor':
      case 'campaign':
      case 'attack-pattern':
        return !!obj.name;
      case 'indicator':
        return !!obj.indicator;
      default:
        return true;
    }
  }

  private interpolateHeaders(headers: Record<string, string>, apiKey: string): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      result[key] = value.replace('${apiKey}', apiKey);
    }
    return result;
  }

  private getNestedProperty(obj: any, path: string): any {
    return path.split('.').reduce((acc, part) => acc && acc[part], obj);
  }

  private async handleFetchError(error: AxiosError, config: FeedProviderConfig, retryCount: number): Promise<GenericStixObject[]> {
    const message = error.response?.data ? JSON.stringify(error.response.data) : error.message;
    this.logger.error(`API request failed for ${config.name}: ${message}`);

    if (error.response?.status === 403) {
      throw new InternalServerErrorException(`Invalid ${config.name} API credentials`);
    }

    const maxRetries = config.maxRetries || DEFAULT_MAX_RETRIES;
    if (
      ([429, 503].includes(error.response?.status) || ['ECONNREFUSED', 'ETIMEDOUT'].includes(error.code || '')) &&
      retryCount < maxRetries
    ) {
      const delay = Math.pow(2, retryCount) * (config.rateLimitDelay || DEFAULT_RATE_LIMIT_DELAY);
      this.logger.warn(`Retrying ${config.name} after ${delay}ms (${retryCount + 1}/${maxRetries})`);
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.fetchStixObjects(config, retryCount + 1);
    }

    throw new InternalServerErrorException(`${config.name} API failed after ${retryCount + 1} attempts: ${message}`);
  }

  private async createRelationships(storedObject: { id: string }, result: EnrichmentResult): Promise<void> {
    const relationships = result.relationships.map(rel => ({
      ...rel,
      source_ref: storedObject.id,
    }));

    if (relationships.length) {
      await Promise.all(
        relationships.map(rel =>
          this.relationshipService.create(rel).catch(err => {
            this.logger.warn(`Failed to create relationship: ${err instanceof Error ? err.message : err}`);
          }),
        ),
      );
    }
  }

  private async storeStixObject(type: StixType, input: StixCreateInput, indicator: GenericStixObject): Promise<{ id: string }> {
    const service = this.serviceFactory.get(type) || this.indicatorService;
    try {
      const storedObject = await service.create(input as any);
      this.logger.log(`Created ${type}: ${storedObject.id}`);
      return storedObject;
    } catch (error) {
      this.logger.error(`Failed to store ${type}: ${error instanceof Error ? error.message : error}`);
      throw new InternalServerErrorException(`Failed to store STIX object: ${error instanceof Error ? error.message : error}`);
    }
  }
}