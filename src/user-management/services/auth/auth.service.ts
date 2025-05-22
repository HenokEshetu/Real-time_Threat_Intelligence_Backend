import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { LoginResponse } from 'src/user-management/types/auth.types';
import { comparePasswords } from 'src/user-management/utils/password.util';
import { AuthSessionService } from './auth-session.service';
import { User } from 'src/user-management/entities/user.entity';
import { TokenPayload } from 'src/user-management/types/auth.types';
import { ConfigService } from '@nestjs/config';
import { AuthenticationError } from '@nestjs/apollo';
import { UserService } from '../user.service';
import { LoginDto } from 'src/user-management/dto/login.dto';
import { AuthValidationService } from './auth-validation.service';
import { ChangePasswordDto } from 'src/user-management/dto/change-password.dto';
import { TokenBlacklistService } from './token-blacklist.service';
import { VaultService } from 'src/security/vault.service';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private authSessionService: AuthSessionService,
    private tokenBlacklistService: TokenBlacklistService,
    private authValidationService: AuthValidationService,
    private vaultService: VaultService,
  ) {}

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const user = await this.authValidationService.validateUserCredentials(
      loginDto.email,
      loginDto.password,
    );

    if (!user || !user.isEmailVerified) {
      throw new UnauthorizedException(
        user ? 'Verify your account' : 'Invalid credentials',
      );
    }

    return {
      access_token: await this.generateAccessToken(user),
      refresh_token: await this.generateRefreshToken(user),
      user,
    };
  }

  async refreshToken(
    refreshToken: string,
  ): Promise<{ access_token: string; user: User }> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      if (await this.tokenBlacklistService.isBlacklisted(refreshToken)) {
        throw new UnauthorizedException('Token revoked');
      }

      const user = await this.userService.findOne(payload.sub);
      return { access_token: await this.generateAccessToken(user), user: user };
    } catch (e) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  private async generateAccessToken(user: User): Promise<string> {
    const payload: TokenPayload = {
      sub: user.userId,
      email: user.email,
      role: user.role?.name || 'user',
      token_type: 'access',
    };
    const { jwt_access_secret: secret, jwt_access_expires_in: expiresIn } =
      await this.vaultService.getSecret('encryption/data/jwt');
    return this.jwtService.sign(payload, {
      expiresIn: expiresIn,
      secret: secret,
    });
  }

  private async generateRefreshToken(user: User): Promise<string> {
    const payload = {
      sub: user.userId,
      token_type: 'refresh',
    };
    const { jwt_refresh_secret: secret, jwt_refresh_expires_in: expiresIn } =
      await this.vaultService.getSecret('encryption/data/jwt');
    return this.jwtService.sign(payload, {
      expiresIn: expiresIn || '3d',
      secret: secret,
    });
  }

  async signOut(token: string): Promise<void> {
    if (!token) {
      throw new AuthenticationError('Token is required');
    }

    await this.authSessionService.signOut(token);
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<void> {
    try {
      const user = await this.userService.findOne(userId);
      const isPasswordValid = await comparePasswords(
        changePasswordDto.oldPassword,
        user.password,
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('Current password is incorrect');
      }

      const hashedPassword = changePasswordDto.newPassword;
      await this.userService.update(userId, { password: hashedPassword });
    } catch (error) {
      console.error('Change password error:', error);
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException(
        'An error occurred while changing password',
      );
    }
  }
}
