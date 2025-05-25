import { Module } from '@nestjs/common';
import { VaultService } from './vault.service';
import VaultClient from 'node-vault-client';
import { ConfigService } from '@nestjs/config';

@Module({
  providers: [
    {
      provide: VaultClient,
      inject: [ConfigService],
      useFactory: (configService: ConfigService) =>
        new VaultClient({
          api: {
            url:
              configService.get<string>('VAULT_ADDR') ||
              'http://localhost:8200',
            apiVersion: 'v1',
          },
          auth: {
            type: 'token',
            config: {
              token: configService.get<string>('VAULT_TOKEN'),
            },
          },
        }),
    },

    VaultService,
  ],
  exports: [VaultService],
})
export class VaultModule {}
