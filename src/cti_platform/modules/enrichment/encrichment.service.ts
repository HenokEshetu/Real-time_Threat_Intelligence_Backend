import { Injectable } from '@nestjs/common';
import { NatsService } from '../microservices/nats/nats.service';

@Injectable()
export class EnrichmentService {
  constructor(private readonly natsService: NatsService) {}

  async enrichIOC(iocData: any): Promise<void> {
    // Publish an IOC enrichment request
    await this.natsService.publish('ioc.enrichment.request', iocData);
  }

  async subscribeToEnrichmentResults(): Promise<void> {
    // Subscribe to enrichment results
    this.natsService.subscribe('ioc.enrichment.result', (data) => {
      console.log('Received IOC enrichment result:', data);
      // Process the result
    });
  }
}
