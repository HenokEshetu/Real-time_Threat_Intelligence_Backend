import { Injectable } from '@nestjs/common';
import { TokenBlacklistService } from './token-blacklist.service';
import { AuthenticationError } from '../../utils/error.util';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { VaultService } from 'src/security/vault.service';

@Injectable()
export class AuthSessionService {
  constructor(
    private tokenBlacklistService: TokenBlacklistService,
    private configService: ConfigService,
    private jwtService: JwtService,
    private vaultService: VaultService,
  ) {}

  async signOut(token: string): Promise<void> {
    try {
      const { exp, token_type } = this.jwtService.decode(token) as {
        exp: number;
        token_type: string;
      };
      const ttl = Math.max(0, exp - Math.floor(Date.now() / 1000));

      await this.tokenBlacklistService.addToBlacklist(
        token,
        ttl,
        token_type as 'access' | 'refresh',
      );
    } catch (error) {
      throw new AuthenticationError('Failed to sign out');
    }
  }

  async validateToken(
    token: string,
    tokenType: 'access' | 'refresh',
  ): Promise<boolean> {
    if (await this.tokenBlacklistService.isBlacklisted(token)) {
      return false;
    }

    try {
      const {
        jwt_access_secret: accessSecret,
        jwt_refresh_secret: refreshSecret,
      } = await this.vaultService.getSecret('encryption/data/jwt');
      this.jwtService.verify(token, {
        secret: this.configService.get<string>(
          tokenType === 'access' ? accessSecret : refreshSecret,
        ),
      });
      return true;
    } catch (e) {
      return false;
    }
  }
}
