import { SetMetadata } from '@nestjs/common';

export const SKIP_VERIFIED_KEY = 'skipVerified';

export const SkipVerified = () => SetMetadata(SKIP_VERIFIED_KEY, true);
