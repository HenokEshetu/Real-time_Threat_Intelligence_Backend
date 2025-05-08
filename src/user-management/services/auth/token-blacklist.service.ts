import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SignOutDto } from 'src/user-management/dto/sign-out.dto';

@Injectable()
export class TokenBlacklistService {
  private blacklistedTokens: Set<string> = new Set();
  private readonly cleanupInterval: NodeJS.Timeout;

  constructor(private configService: ConfigService) {
    // Clean up expired tokens every hour
    this.cleanupInterval = setInterval(() => this.cleanupExpiredTokens(), 3600000);
  }

  async addToBlacklist(token): Promise<void> {
    this.blacklistedTokens.add(token);
  }

  async isBlacklisted(token: string): Promise<boolean> {
    return this.blacklistedTokens.has(token);
  }

  private cleanupExpiredTokens(): void {
    // Implementation for cleaning up expired tokens
    // This would be more sophisticated in a production environment
    // potentially using Redis or another persistent store
  }

  onModuleDestroy() {
    clearInterval(this.cleanupInterval);
  }
}