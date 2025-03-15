import { Injectable } from '@nestjs/common';
import { RedisService } from '../../../modules/microservices/redis/redis.service';

@Injectable()
export class CacheService {
  constructor(private readonly redisService: RedisService) {}

  async cacheData(key: string, data: string, ttl?: number): Promise<void> {
    await this.redisService.set(key, data, ttl);
  }

  async getCachedData(key: string): Promise<string | null> {
    return await this.redisService.get(key);
  }

  async deleteCachedData(key: string): Promise<void> {
    await this.redisService.delete(key);
  }
}
