// src/cti_platform/modules/stix-objects/stix-objects.service.ts
import { Injectable } from '@nestjs/common';
import { NatsService } from '../microservices/nats/nats.service';

@Injectable()
export class StixObjectsService {
  constructor(private readonly natsService: NatsService) {}

  async createStixObject(stixObject: any): Promise<void> {
    // Publish a STIX object creation event
    await this.natsService.publish('stix.object.created', stixObject);
  }

  async subscribeToStixObjectUpdates(): Promise<void> {
    // Subscribe to STIX object updates
    this.natsService.subscribe('stix.object.updated', (data) => {
      console.log('Received STIX object update:', data);
      // Process the update
    });
  }
}
