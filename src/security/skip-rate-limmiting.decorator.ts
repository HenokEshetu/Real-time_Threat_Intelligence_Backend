import { SetMetadata } from '@nestjs/common';

export const SKIP_RATE_LIMITING_KEY = 'skipRateLimiting';
export const SkipRateLimiting = () => SetMetadata(SKIP_RATE_LIMITING_KEY, true);
