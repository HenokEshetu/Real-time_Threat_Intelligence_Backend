import { Module } from '@nestjs/common';
import { EnrichmentModule } from './modules/enrichment/enrichment.module';
import { IngestionFromApiFeedsModule } from './modules/ingestion-from-api-feeds/ingestion-from-api-feeds.module';
import { StixObjectsModule } from './modules/stix-objects/stix-objects.module';
import { RateLimiterService } from 'src/security/rate-limitter.service';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { RateLimiterGuard } from 'src/security/rate-limmiter.guard';

@Module({
  imports: [EnrichmentModule, IngestionFromApiFeedsModule, StixObjectsModule],
  providers: [
    RateLimiterService,
    {
      provide: APP_GUARD,
      useFactory: (
        rateLimiterService: RateLimiterService,
        reflector: Reflector,
      ) => new RateLimiterGuard(rateLimiterService, 100, 60, reflector),
      inject: [RateLimiterService, Reflector],
    },
  ],
})
export class CtiPlatformModule {}
