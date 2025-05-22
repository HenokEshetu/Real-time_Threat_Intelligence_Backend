import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from 'src/user-management/entities/user.entity';
import { TokenPayload, TokenType } from 'src/user-management/types/auth.types';
import { Roles } from 'src/user-management/roles-permissions/role.enum';
import { VaultService } from 'src/security/vault.service';

@Injectable()
export class AuthTokenService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    private vaultService: VaultService,
  ) {}

  createTokenPayload(user: User, tokenType: TokenType): TokenPayload {
    return {
      sub: user.userId,
      email: user.email,
      role: user.role?.name || Roles.User,
      token_type: tokenType,
    };
  }

  async generateToken(payload: TokenPayload): Promise<string> {
    const secret = await this.getSecret(payload.token_type);
    const expiresIn = await this.getExpiration(payload.token_type);

    return this.jwtService.sign(payload, {
      secret,
      expiresIn,
    });
  }

  async verifyToken(
    token: string,
    tokenType: TokenType,
  ): Promise<TokenPayload> {
    return this.jwtService.verify(token, {
      secret: await this.getSecret(tokenType),
    });
  }

  private async getSecret(tokenType: TokenType): Promise<string> {
    const {
      jwt_access_secret: accessSecret,
      jwt_refresh_secret: refreshSecret,
    } = await this.vaultService.getSecret('encryption/data/jwt');
    return tokenType === 'access' ? accessSecret : refreshSecret;
  }

  private async getExpiration(tokenType: TokenType): Promise<string> {
    const {
      jwt_access_expires_in: accessExpiresIn,
      jwt_refresh_expires_in: refreshExpiresIn,
    } = await this.vaultService.getSecret('encryption/data/jwt');
    return tokenType === 'access' ? accessExpiresIn : refreshExpiresIn;
  }
}
