import { JwtService } from '@nestjs/jwt';
import { User } from '../entities/user.entity';
import { TokenPayload } from '../types/auth.types';

export const createTokenPayload = (user: User): TokenPayload => ({
  sub: user.id,
  email: user.email,
  roles: user.roles.map(role => role.name),
});

export const generateToken = (
  jwtService: JwtService,
  payload: TokenPayload,
): string => {
  return jwtService.sign(payload);
};