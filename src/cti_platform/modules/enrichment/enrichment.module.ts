import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { EnrichmentService } from './enrichment.service';

@Module({
  imports: [HttpModule],
  providers: [EnrichmentService],
  exports: [EnrichmentService, HttpModule],
})
export class EnrichmentModule {}
