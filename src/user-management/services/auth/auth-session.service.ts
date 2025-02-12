import { Injectable } from '@nestjs/common';
import { TokenBlacklistService } from 'src/user-management/services/auth/auth-token/token-blacklist.service';
import { AuthenticationError } from '../../utils/error.util';
import { SignOutDto } from 'src/user-management/dto/sign-out.dto';

@Injectable()
export class AuthSessionService {
  constructor(private tokenBlacklistService: TokenBlacklistService) {}

  async signOut(token: SignOutDto): Promise<void> {
    try {
      await this.tokenBlacklistService.addToBlacklist(token);
    } catch (error) {
      throw new AuthenticationError('Failed to sign out');
    }
  }

  async validateToken(token: string): Promise<boolean> {
    return !(await this.tokenBlacklistService.isBlacklisted(token));
  }
}