import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { RedisModule as NestRedisModule } from '@nestjs-modules/ioredis';
import { REDIS_CONFIG_KEY, RedisConfig } from '../../../config/redis.config';

@Module({
  imports: [
    NestRedisModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'single',
        url: `redis://${configService.get<RedisConfig>(REDIS_CONFIG_KEY).host}:${configService.get<RedisConfig>(REDIS_CONFIG_KEY).port}`,
        options: {
          password: configService.get<RedisConfig>(REDIS_CONFIG_KEY).password,
          db: configService.get<RedisConfig>(REDIS_CONFIG_KEY).db,
          tls: configService.get<RedisConfig>(REDIS_CONFIG_KEY).tls
            ? {}
            : undefined,
        },
      }),
    }),
  ],
  exports: [NestRedisModule],
})
export class RedisModule {}
