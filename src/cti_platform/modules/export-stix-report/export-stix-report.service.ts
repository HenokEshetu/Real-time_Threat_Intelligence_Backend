import { Injectable } from '@nestjs/common';
import { NatsService } from '../microservices/nats/nats.service';

@Injectable()
export class ExportStixReportService {
  constructor(private readonly natsService: NatsService) {}

  async exportReport(reportData: any): Promise<void> {
    // Publish a report export request
    await this.natsService.publish('report.export.request', reportData);
  }

  async subscribeToExportResults(): Promise<void> {
    // Subscribe to report export results
    this.natsService.subscribe('report.export.result', (data) => {
      console.log('Received report export result:', data);
      // Process the result
    });
  }
}
