import { Injectable } from '@nestjs/common';
import { NatsService } from '../microservices/nats/nats.service';

@Injectable()
export class AnalysisAndThreatCorrelationService {
  constructor(private readonly natsService: NatsService) {}

  async analyzeThreat(threatData: any): Promise<void> {
    // Publish a threat analysis request
    await this.natsService.publish('threat.analysis.request', threatData);
  }

  async subscribeToThreatAnalysis(): Promise<void> {
    // Subscribe to threat analysis results
    this.natsService.subscribe('threat.analysis.result', (data) => {
      console.log('Received threat analysis result:', data);
      // Process the result
    });
  }
}
