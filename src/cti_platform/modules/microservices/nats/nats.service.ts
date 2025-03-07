import { Injectable, Inject, OnModuleInit } from '@nestjs/common';
import { ClientProxy } from '@nestjs/microservices';
import { firstValueFrom, timeout } from 'rxjs';
import { NATS_CONFIG_KEY, NatsConfig } from '../../../config/nats.config';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class NatsService implements OnModuleInit {
  constructor(
    @Inject('NATS_CLIENT') private readonly client: ClientProxy,
    private readonly configService: ConfigService,
  ) {}

  async onModuleInit() {
    await this.client.connect();
  }

  async publish(pattern: string, data: any): Promise<void> {
    this.client.emit(pattern, data);
  }

  async send<T>(pattern: string, data: any): Promise<T> {
    const natsConfig = this.configService.get<NatsConfig>(NATS_CONFIG_KEY);
    return await firstValueFrom(
      this.client.send<T>(pattern, data).pipe(timeout(natsConfig.timeout)),
    );
  }

  subscribe(pattern: string, callback: (data: any) => void): void {
    this.client.connect().then(() => {
      this.client.send(pattern, {}).subscribe(callback);
    });
  }
}
