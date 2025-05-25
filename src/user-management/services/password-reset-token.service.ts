import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';

@Injectable()
export class PasswordResetTokenService {
  generateToken(): string {
    return randomBytes(64).toString('hex');
  }

  generateExpirationDate(): Date {
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 5); // Token expires in 5 minutes
    return expiresAt;
  }
}
