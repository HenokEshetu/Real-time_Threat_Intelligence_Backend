import { JwtService } from '@nestjs/jwt';
import { User } from '../entities/user.entity';
import { TokenPayload } from '../types/auth.types';
import { Roles } from 'src/user-management/roles-permissions/role.enum';

export const createTokenPayload = (
  user: User,
  token_type: 'access' | 'refresh',
): TokenPayload => ({
  sub: user.userId,
  email: user.email,
  role: user.role?.name || Roles.User,
  token_type: token_type,
});

export const generateToken = (
  jwtService: JwtService,
  payload: TokenPayload,
): string => {
  return jwtService.sign(payload);
};
