import { registerAs } from '@nestjs/config';
import * as Joi from 'joi';

export interface NatsConfig {
  url: string;
  queueGroup: string;
  maxReconnectAttempts: number;
  reconnectTimeWait: number;
  timeout: number;
}

export const NATS_CONFIG_KEY = 'nats';

export default registerAs(NATS_CONFIG_KEY, () => ({
  url: process.env.NATS_URL || 'nats://localhost:4222',
  queueGroup: process.env.NATS_QUEUE_GROUP || 'cti-platform',
  maxReconnectAttempts: parseInt(process.env.NATS_MAX_RECONNECT_ATTEMPTS || '5', 10),
  reconnectTimeWait: parseInt(process.env.NATS_RECONNECT_TIME_WAIT || '5000', 10), // 5 seconds
  timeout: parseInt(process.env.NATS_TIMEOUT || '10000', 10), // 10 seconds
}));

export const natsConfigSchema = Joi.object({
  NATS_URL: Joi.string().uri().default('nats://localhost:4222'),
  NATS_QUEUE_GROUP: Joi.string().default('cti-platform'),
  NATS_MAX_RECONNECT_ATTEMPTS: Joi.number().default(5),
  NATS_RECONNECT_TIME_WAIT: Joi.number().default(5000),
  NATS_TIMEOUT: Joi.number().default(10000),
});
