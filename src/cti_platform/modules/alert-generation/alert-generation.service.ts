import { Injectable } from '@nestjs/common';
import { NatsService } from '../microservices/nats/nats.service';

@Injectable()
export class AlertGenerationService {
  constructor(private readonly natsService: NatsService) {}

  async generateAlert(alertData: any): Promise<void> {
    // TODO: Publish an alert to the NATS topic
    await this.natsService.publish('alert.generated', alertData);
  }

  async requestAnalysis(data: any): Promise<any> {
    // TODO: Send a request and wait for a response
    return await this.natsService.send<any>('analysis.request', data);
  }
}
