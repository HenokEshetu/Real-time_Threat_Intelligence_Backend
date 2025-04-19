
import * as Joi from 'joi';

export interface ApiConfig {
  url: string;
  apiKeyEnv?: string;
  requiredKey?: boolean;
  rateLimit: { maxRequests: number; perMilliseconds: number };
  headers?: Record<string, string>;
  params?: Record<string, any>;
  method?: 'get' | 'post';
  data?: any;
  timeout?: number;
  retryPolicy?: RetryPolicy;
}

export interface RetryPolicy {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
}

export interface EnrichmentTaskConfig {
  service: string;
  fetchFn: string; // Name of the fetch function (e.g., 'fetchVirusTotalData')
  field: string;
  validator?: string; // Regex pattern or function name for validation
  schema?: string; // Reference to schema key in enrichmentSchemas
  priority?: number;
}

export interface EnrichmentConfig {
  apiConfigs: Record<string, ApiConfig>;
  enrichmentSchemas: Record<string, Joi.ObjectSchema>;
  enrichmentRegistry: Record<string, EnrichmentTaskConfig[]>;
}


