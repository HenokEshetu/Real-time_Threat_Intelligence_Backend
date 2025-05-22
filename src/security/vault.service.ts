import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import VaultClient from 'node-vault-client';

@Injectable()
export class VaultService implements OnModuleInit {
  private readonly logger = new Logger(VaultService.name);
  private vault: any;

  constructor(private configService: ConfigService) {
    this.vault = VaultClient.boot('main', {
      api: { url: this.configService.get<string>('vault.addr') },
      auth: {
        type: 'token',
        config: { token: this.configService.get<string>('vault.token') },
      },
    });
  }

  async onModuleInit() {
    try {
      await this.vault.read('sys/health');
      this.logger.log('Connected to Vault successfully');
    } catch (error) {
      this.logger.error('Vault connection failed', error.stack);
      throw error;
    }
  }

  async getSecret(path: string): Promise<Record<string, any>> {
    try {
      const lease = await this.vault.read(path);
      // node-vault-client returns a Lease, whose real payload is in __data.data
      const secretData = (lease as any).__data?.data;
      if (!secretData) {
        throw new Error(`No secret data found at path "${path}"`);
      }
      return secretData;
    } catch (error) {
      this.logger.error(`Failed to retrieve secret from ${path}`, error.stack);
      throw error;
    }
  }

  async rotateKeys() {
    try {
      const newEncryptionKey = this.generateHex(64);
      const newEncryptionIV = this.generateHex(16);
      const newJwtAccessSecret = this.generateHex(64);
      const newJwtRefreshSecret = this.generateHex(64);

      await this.vault.write('encryption/data/jwt', {
        data: {
          encryption_key: newEncryptionKey,
          encryption_iv: newEncryptionIV,
          jwt_access_secret: newJwtAccessSecret,
          jwt_refresh_secret: newJwtRefreshSecret,
        },
      });

      return { success: true };
    } catch (error) {
      this.logger.error('Key rotation failed', error.stack);
      throw error;
    }
  }

  private generateHex(bytes: number): string {
    return require('crypto').randomBytes(bytes).toString('hex');
  }
}
