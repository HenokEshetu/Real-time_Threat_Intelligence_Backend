import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, RedisClientType } from 'redis';
import * as crypto from 'crypto';
import { VaultService } from 'src/security/vault.service';

@Injectable()
export class TokenBlacklistService {
  private redisClient: RedisClientType;

  constructor(
    private configService: ConfigService,
    private vaultService: VaultService,
  ) {
    this.redisClient = createClient({
      url: this.configService.get<string>('REDIS_URL'),
    });
    this.redisClient.connect();
  }

  async addToBlacklist(
    token: string,
    ttl: number,
    tokenType: 'access' | 'refresh',
  ): Promise<void> {
    const encrypted = this.encryptToken(token);
    await this.redisClient.setEx(
      `${tokenType}_blacklist:${encrypted}`,
      ttl,
      '1',
    );
  }

  async isBlacklisted(token: string): Promise<boolean> {
    const accessKey = `access_blacklist:${this.encryptToken(token)}`;
    const refreshKey = `refresh_blacklist:${this.encryptToken(token)}`;

    const exists = await Promise.all([
      this.redisClient.exists(accessKey),
      this.redisClient.exists(refreshKey),
    ]);

    return exists.some(Boolean);
  }

  private async encryptToken(token: string): Promise<string> {
    const { encryption_key, encryption_iv } = await this.vaultService.getSecret(
      'encryption/data/jwt',
    );
    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      Buffer.from(encryption_key, 'hex'),
      Buffer.from(encryption_iv, 'hex'),
    );
    return cipher.update(token, 'utf8', 'hex') + cipher.final('hex');
  }

  async onModuleDestroy() {
    await this.redisClient.quit();
  }
}
