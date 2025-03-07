import { Injectable } from '@nestjs/common';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';

@Injectable()
export class RedisService {
  constructor(@InjectRedis() private readonly redis: Redis) {}

  async set(key: string, value: string, ttl?: number): Promise<void> {
    await this.redis.set(key, value);
    if (ttl) {
      await this.redis.expire(key, ttl);
    }
  }

  async get(key: string): Promise<string | null> {
    return this.redis.get(key);
  }

  async disconnect(): Promise<void> {
    await this.redis.quit();
    console.log('Redis connection closed');
  }

  async onModuleDestroy(): Promise<void> {
    await this.disconnect();
  }
};
