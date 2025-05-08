import * as crypto from 'crypto';

export const generateVerificationToken = (): string => {
  return crypto.randomBytes(64).toString('hex');
}
