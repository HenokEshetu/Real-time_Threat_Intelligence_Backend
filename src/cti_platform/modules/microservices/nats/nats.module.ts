// src/cti_platform/core/utils/nats/nats.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { NATS_CONFIG_KEY, NatsConfig } from '../../../config/nats.config';

@Module({
  imports: [
    ClientsModule.registerAsync([
      {
        name: 'NATS_CLIENT',
        imports: [ConfigModule],
        inject: [ConfigService],
        useFactory: (configService: ConfigService) => ({
          transport: Transport.NATS,
          options: {
            servers: [configService.get<NatsConfig>(NATS_CONFIG_KEY).url],
            queue: configService.get<NatsConfig>(NATS_CONFIG_KEY).queueGroup,
            maxReconnectAttempts: configService.get<NatsConfig>(NATS_CONFIG_KEY).maxReconnectAttempts,
            reconnectTimeWait: configService.get<NatsConfig>(NATS_CONFIG_KEY).reconnectTimeWait,
            timeout: configService.get<NatsConfig>(NATS_CONFIG_KEY).timeout,
          },
        }),
      },
    ]),
  ],
  exports: [ClientsModule],
})
export class NatsModule {}
