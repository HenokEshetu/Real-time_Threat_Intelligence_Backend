import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from 'src/user-management/types/auth.types';
import { User } from 'src/user-management/entities/user.entity';

@Injectable()
export class AuthTokenService {
  constructor(private jwtService: JwtService) {}

  createTokenPayload(user: User): TokenPayload {
    return {
      sub: user.id,
      email: user.email,
      roles: user.roles?.map(role => role.name) || [],
    };
  }

  generateToken(payload: TokenPayload): string {
    return this.jwtService.sign(payload);
  }

  verifyToken(token: string): TokenPayload {
    return this.jwtService.verify(token);
  }
}