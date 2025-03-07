import { registerAs } from '@nestjs/config';
import * as Joi from 'joi';

export interface RedisConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  tls?: boolean;
  ttl?: number; // Time-to-live in seconds
}

export const REDIS_CONFIG_KEY = 'redis';

export default registerAs(REDIS_CONFIG_KEY, () => ({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379', 10),
  password: process.env.REDIS_PASSWORD,
  db: parseInt(process.env.REDIS_DB || '0', 10),
  tls: process.env.REDIS_TLS === 'true',
  ttl: parseInt(process.env.REDIS_TTL || '3600', 10), // Default TTL: 1 hour
}));

export const redisConfigSchema = Joi.object({
  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().port().default(6379),
  REDIS_PASSWORD: Joi.string().optional(),
  REDIS_DB: Joi.number().default(0),
  REDIS_TLS: Joi.boolean().default(false),
  REDIS_TTL: Joi.number().default(3600), // Default TTL: 1 hour
});
