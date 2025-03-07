import { Injectable } from '@nestjs/common';
import { NatsService } from '../cti_platform/modules/microservices/nats/nats.service';

@Injectable()
export class UserManagementService {
  constructor(private readonly natsService: NatsService) {}

  async createUser(userData: any): Promise<void> {
    // Publish a user creation event
    await this.natsService.publish('user.created', userData);
  }

  async subscribeToUserEvents(): Promise<void> {
    // Subscribe to user-related events
    this.natsService.subscribe('user.*', (data) => {
      console.log('Received user event:', data);
      // Process the event
    });
  }
}
