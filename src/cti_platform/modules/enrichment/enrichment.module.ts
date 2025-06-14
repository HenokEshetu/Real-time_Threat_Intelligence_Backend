import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { EnrichmentService } from './enrichment.service';
import { EnrichmentConfig } from 'config/enrichment-config.interface';
import { Enrichment } from 'src/cti_platform/core/types/common-data-types';
@Module({
  imports: [
    HttpModule, 
    EventEmitterModule.forRoot(),
  ],
  providers: [EnrichmentService, ],
  exports: [EnrichmentService, HttpModule],
})
export class EnrichmentModule {}
