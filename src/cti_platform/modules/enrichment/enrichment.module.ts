import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { EnrichmentService } from './enrichment.service';

@Module({
  imports: [
    HttpModule,
    EventEmitterModule.forRoot(),
  ],
  providers: [EnrichmentService],
  exports: [EnrichmentService, HttpModule],
})
export class EnrichmentModule {}
