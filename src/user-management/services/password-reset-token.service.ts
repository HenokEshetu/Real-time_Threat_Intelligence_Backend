import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';

@Injectable()
export class PasswordResetTokenService {
  generateToken(): string {
    return randomBytes(32).toString('hex');
  }

  generateExpirationDate(): Date {
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24); // Token expires in 24 hours
    return expiresAt;
  }
}