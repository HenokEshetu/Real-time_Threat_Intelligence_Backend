import { Injectable } from '@nestjs/common';
import { AuthenticationError } from '../../utils/error.util';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { VaultService } from 'src/security/vault.service';

@Injectable()
export class AuthSessionService {
  // In-memory blacklist (for short-term storage)
  private tokenBlacklist = new Map<string, number>();
  private cleanupInterval: NodeJS.Timeout;

  constructor(
    private configService: ConfigService,
    private jwtService: JwtService,
    private vaultService: VaultService,
  ) {
    // Setup cleanup interval (every 5 minutes)
    this.cleanupInterval = setInterval(
      () => this.cleanupExpiredEntries(),
      300_000,
    );
  }

  onModuleDestroy() {
    clearInterval(this.cleanupInterval);
  }

  private cleanupExpiredEntries() {
    const now = Date.now();
    for (const [token, expiry] of this.tokenBlacklist) {
      if (expiry <= now) {
        this.tokenBlacklist.delete(token);
      }
    }
  }

  async signOut(token: string): Promise<void> {
    try {
      if (!token) return;

      const decoded = this.jwtService.decode(token);
      if (!decoded || typeof decoded === 'string') {
        throw new Error('Invalid token format');
      }

      const { exp } = decoded as { exp: number };
      const expiryTimestamp = exp * 1000; // Convert to milliseconds

      // Add to in-memory blacklist with expiration timestamp
      this.tokenBlacklist.set(token, expiryTimestamp);
    } catch (error) {
      console.error('Token revocation failed:', error);
      throw new AuthenticationError('Failed to sign out');
    }
  }

  async validateToken(
    token: string,
    tokenType: 'access' | 'refresh',
  ): Promise<boolean> {
    try {
      // Check in-memory blacklist first
      if (this.tokenBlacklist.has(token)) {
        return false;
      }

      // Validate token signature and expiration
      const secrets = await this.vaultService.getSecret('encryption/data/jwt');
      const secret = this.configService.get<string>(
        tokenType === 'access'
          ? secrets.jwt_access_secret
          : secrets.jwt_refresh_secret,
      );

      this.jwtService.verify(token, { secret });
      return true;
    } catch (e) {
      return false;
    }
  }
}
