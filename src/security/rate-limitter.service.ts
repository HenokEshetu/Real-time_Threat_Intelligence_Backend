import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, RedisClientType } from 'redis';

@Injectable()
export class RateLimiterService {
  private redisClient: RedisClientType;

  constructor(private configService: ConfigService) {
    this.redisClient = createClient({
      url: this.configService.get<string>('REDIS_URL'),
    });
    this.redisClient.connect();
  }

  async checkRateLimit(
    identifier: string,
    limit: number,
    windowSeconds: number,
  ): Promise<{ allowed: boolean; remaining: number }> {
    const key = `rate_limit:${identifier}`;
    const current = await this.redisClient.incr(key);

    if (current === 1) {
      await this.redisClient.expire(key, windowSeconds);
    }

    const remaining = Math.max(limit - current, 0);
    return { allowed: current <= limit, remaining };
  }

  async cleanup() {
    await this.redisClient.quit();
  }
}
