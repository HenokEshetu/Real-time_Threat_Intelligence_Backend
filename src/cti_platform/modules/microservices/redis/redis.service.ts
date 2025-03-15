import { Injectable, Inject } from '@nestjs/common';
import { Redis } from 'ioredis';
import { REDIS_CONFIG_KEY, RedisConfig } from '../../../config/redis.config';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class RedisService {
  private readonly ttl: number;

  constructor(
    @Inject('REDIS_CLIENT') private readonly redisClient: Redis,
    private readonly configService: ConfigService,
  ) {
    const redisConfig = this.configService.get<RedisConfig>(REDIS_CONFIG_KEY);
    this.ttl = redisConfig.ttl || 3600; // Default TTL: 1 hour
  }

  async set(key: string, value: string, ttl?: number): Promise<void> {
    await this.redisClient.set(key, value, 'EX', ttl || this.ttl);
  }

  async get(key: string): Promise<string | null> {
    return await this.redisClient.get(key);
  }

  async delete(key: string): Promise<void> {
    await this.redisClient.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.redisClient.exists(key);
    return result === 1;
  }

  async expire(key: string, ttl: number): Promise<void> {
    await this.redisClient.expire(key, ttl);
  }
}
