import { Module } from '@nestjs/common';
// Import submodules
import { AddStixReportManuallyModule } from './modules/add-stix-report-manually/add-stix-report-manually.module';
import { AlertGenerationModule } from './modules/alert-generation/alert-generation.module';

import { EnrichmentModule } from './modules/enrichment/enrichment.module';
import { ExportStixReportModule } from './modules/export-stix-report/export-stix-report.module';
import { IngestionFromApiFeedsModule } from './modules/ingestion-from-api-feeds/ingestion-from-api-feeds.module';
import { IntegrationModule } from './modules/integration/integration.module';
import { StixObjectsModule } from './modules/stix-objects/stix-objects.module';
import { ConfigModule } from '@nestjs/config';
import Joi from 'joi';
import natsConfig, { natsConfigSchema } from './config/nats.config';
import redisConfig, { redisConfigSchema } from './config/redis.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [redisConfig, natsConfig],
      validationSchema: Joi.object({
        redisConfigSchema,
        natsConfigSchema,
      }),
    }),
    
    AddStixReportManuallyModule,
    AlertGenerationModule,
    
    EnrichmentModule,
    ExportStixReportModule,
    IngestionFromApiFeedsModule,
    IntegrationModule,
    StixObjectsModule,
  ],
  providers: [

  ],

})
export class CtiPlatformModule {}
