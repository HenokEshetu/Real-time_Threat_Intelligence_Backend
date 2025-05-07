import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Request } from 'express';
import { UserService } from 'src/user-management/services/user.service';

export interface JwtAuthPayload {
  sub: string;
  email: string;
  roles: string[];
  iat: number;
  exp: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    private userService: UserService,
    private configService: ConfigService
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => {
          const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
          return token;
        }
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get('auth.jwtSecret') || 'your-secret-key',
    });
  }

  async validate(payload: JwtAuthPayload) {
    const user = await this.userService.findOne(payload.sub);

    if (!user) {
      this.logger.warn(`User not found for sub: ${payload.sub}`);
      throw new Error('User not found');
    }

    return user;
  }
}
