import { Module } from '@nestjs/common';
import { EnrichmentModule } from './modules/enrichment/enrichment.module';
import { IngestionFromApiFeedsModule } from './modules/ingestion-from-api-feeds/ingestion-from-api-feeds.module';
import { StixObjectsModule } from './modules/stix-objects/stix-objects.module';

@Module({
  imports: [
    EnrichmentModule,
    IngestionFromApiFeedsModule,
    StixObjectsModule,
  ],
  providers: [

  ],

})
export class CtiPlatformModule {}
