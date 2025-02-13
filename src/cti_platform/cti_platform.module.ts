import { Module } from '@nestjs/common';
import { AddStixReportManuallyModule } from './modules/add-stix-report-manually/add-stix-report-manually.module';
import { AlertGenerationModule } from './modules/alert-generation/alert-generation.module';
import { AnalysisAndThreatCorrelationModule } from './modules/analysis-and-threat-correlation/analysis-and-threat-correlation.module';
import { EnrichmentModule } from './modules/enrichment/enrichment.module';
import { ExportStixReportModule } from './modules/export-stix-report/export-stix-report.module';
import { IngestionFromApiFeedsModule } from './modules/ingestion-from-api-feeds/ingestion-from-api-feeds.module';
import { IntegrationModule } from './modules/integration/integration.module';
import { MitreAttackMappingModule } from './modules/mitre-attack-mapping/mitre-attack-mapping.module';
import { StixObjectsModule } from './modules/stix-objects/stix-objects.module';

@Module({
  imports: [
    AddStixReportManuallyModule,
    AlertGenerationModule,
    AnalysisAndThreatCorrelationModule,
    EnrichmentModule,
    ExportStixReportModule,
    IngestionFromApiFeedsModule,
    IntegrationModule,
    MitreAttackMappingModule,
    StixObjectsModule,
  ],
})
export class CtiPlatformModule {}


