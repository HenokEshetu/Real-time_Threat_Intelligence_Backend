import { Injectable } from '@nestjs/common';
import { NatsService } from '../microservices/nats/nats.service';

@Injectable()
export class IngestionFromApiFeedsService {
  constructor(private readonly natsService: NatsService) {}

  async ingestData(feedData: any): Promise<void> {
    // Publish ingested data
    await this.natsService.publish('data.ingested', feedData);
  }

  async subscribeToIngestionErrors(): Promise<void> {
    // Subscribe to ingestion errors
    this.natsService.subscribe('data.ingestion.error', (error) => {
      console.error('Ingestion error:', error);
      // Handle the error
    });
  }
}
