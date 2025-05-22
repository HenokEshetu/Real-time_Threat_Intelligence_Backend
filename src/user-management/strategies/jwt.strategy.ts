import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserService } from 'src/user-management/services/user.service';
import { VaultService } from 'src/security/vault.service';

export interface JwtAuthPayload {
  sub: string;
  email: string;
  role: string;
  iat: number;
  exp: number;
}

@Injectable()
export class JwtStrategy
  extends PassportStrategy(Strategy, 'jwt')
  implements OnModuleInit
{
  private readonly logger = new Logger(JwtStrategy.name);
  private secret: string;

  constructor(
    private readonly userService: UserService,
    private readonly vaultService: VaultService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => {
          const token = ExtractJwt.fromAuthHeaderAsBearerToken()(req);
          return token;
        },
      ]),
      ignoreExpiration: false,
      secretOrKeyProvider: (req, token, done) => {
        if (!this.secret) {
          this.logger.error('JWT secret not initialized');
          return done(new Error('Authentication service unavailable'), null);
        }
        return done(null, this.secret);
      },
      passReqToCallback: true,
    });
  }

  async onModuleInit() {
    try {
      const { jwt_access_secret: secret } = await this.vaultService.getSecret(
        'encryption/data/jwt',
      );
      this.secret = secret;
    } catch (error) {
      this.logger.error('Failed to initialize JWT strategy', error.stack);
      throw new Error('Critical: Failed to load JWT secret');
    }
  }

  async validate(request: Request, payload: JwtAuthPayload) {
    try {
      const user = await this.userService.findOne(payload.sub);
      if (!user) {
        this.logger.warn(`User not found for sub: ${payload.sub}`);
        throw new Error('Unauthorized - User account not found');
      }

      if (user.deletionRequested) {
        this.logger.warn(`Suspended user attempt: ${payload.email}`);
        throw new Error('Unauthorized - Account suspended');
      }

      this.logger.log(`Authenticated user: ${user.email}`);
      return user;
    } catch (error) {
      this.logger.error(
        `Validation error for sub ${payload.sub}: ${error.message}`,
      );
      throw new Error('Authentication validation failed');
    }
  }
}
