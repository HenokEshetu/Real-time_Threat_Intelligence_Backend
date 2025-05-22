import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';

import { Permission } from './entities/permission.entity';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';

import { PasswordReset } from './entities/password-reset.entity';

import { UserService } from './services/user.service';
import { RoleService } from './services/role.service';
import { PermissionService } from './services/permission.service';
import { UserService } from './services/user.service';
import { RoleService } from './services/role.service';
import { PermissionService } from './services/permission.service';
import { AuthService } from './services/auth/auth.service';
import { UserQueryService } from './services/user-query.service';
import { UserCommandService } from './services/user-command.service';
import { AuthValidationService } from './services/auth/auth-validation.service';
import { AuthTokenService } from './services/auth/auth-token.service';
import { UserQueryService } from './services/user-query.service';
import { UserCommandService } from './services/user-command.service';
import { AuthValidationService } from './services/auth/auth-validation.service';
import { AuthTokenService } from './services/auth/auth-token.service';
import { PasswordResetService } from './services/password-reset.service';
import { PasswordResetTokenService } from './services/password-reset-token.service';
import { TokenBlacklistService } from './services/auth/token-blacklist.service';
import { TokenBlacklistService } from './services/auth/token-blacklist.service';
import { AuthSessionService } from './services/auth/auth-session.service';

import { UserResolver } from './resolvers/user.resolver';
import { AuthResolver } from './resolvers/auth.resolver';
import { UserResolver } from './resolvers/user.resolver';
import { AuthResolver } from './resolvers/auth.resolver';
import { PasswordResetResolver } from './resolvers/password-reset.resolver';

import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { GoogleStrategy } from './strategies/google.strategy';

import databaseConfig from '../config/database.config';
import { EmailVerificationToken } from './entities/email-verification-token.entity';
import { EmailVerificationService } from './services/email-verification.service';
import { MailerModule } from '@nestjs-modules/mailer';
import { join } from 'path';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { EmailVerificationResolver } from './resolvers/email-verification.resolver';
import emailConfig from '../config/emai.config';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { VaultService } from 'src/security/vault.service';
import { VaultModule } from 'src/security/vault.module';
import { RateLimiterService } from 'src/security/rate-limitter.service';
import { RateLimiterGuard } from 'src/security/rate-limmiter.guard';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, emailConfig],
    }),

    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        ...configService.get('database'),
        autoLoadEntities: true,
        synchronize: true,
      }),
    }),

    TypeOrmModule.forFeature([
      User,
      Role,
      Permission,
      PasswordReset,
      EmailVerificationToken,
    ]),

    TypeOrmModule.forFeature([
      User,
      Role,
      Permission,
      PasswordReset,
      EmailVerificationToken,
    ]),

    PassportModule.register({ defaultStrategy: 'jwt' }),

    VaultModule,

    JwtModule.registerAsync({
      imports: [ConfigModule, VaultModule],
      inject: [VaultService],
      useFactory: async (vaultService: VaultService) => {
        const {
          jwt_access_secret: access,
          jwt_access_expires_in: accessExpires,
        } = await vaultService.getSecret('encryption/data/jwt');
        return {
          secret: access,
          signOptions: {
            expiresIn: accessExpires || '15m',
          },
        };
      },
    }),

    JwtModule.registerAsync({
      imports: [ConfigModule, VaultModule],
      inject: [VaultService],
      useFactory: async (vaultService: VaultService) => {
        const {
          jwt_refresh_secret: refresh,
          jwt_refresh_expires_in: refreshExpires,
        } = await vaultService.getSecret('encryption/data/jwt');
        return {
          secret: refresh,
          signOptions: {
            expiresIn: refreshExpires || '1d',
          },
        };
      },
    }),

    MailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        transport: {
          host: config.get<string>('email.host'),
          port: Number(config.get<string>('email.port')),
          auth: {
            user: config.get<string>('email.user'),
            pass: config.get<string>('email.password'),
          },
        },
        template: {
          dir: join(__dirname, 'email-templates'),
          adapter: new HandlebarsAdapter(),
          options: {
            restrict: true,
          },
        },
      }),
    }),
  ],

  providers: [
    UserService,
    AuthService,
    RoleService,
    PermissionService,
    AuthSessionService,

    AuthValidationService,
    AuthTokenService,
    TokenBlacklistService,

    UserQueryService,
    UserCommandService,

    PasswordResetService,
    PasswordResetTokenService,

    UserResolver,
    AuthResolver,
    PasswordResetResolver,
    EmailVerificationResolver,
    EmailVerificationResolver,

    JwtAuthGuard,
    JwtStrategy,
    LocalStrategy,
    GoogleStrategy,

    EmailVerificationService,

    RateLimiterService,
    {
      provide: APP_GUARD,
      useFactory: (
        rateLimiterService: RateLimiterService,
        reflector: Reflector,
      ) => new RateLimiterGuard(rateLimiterService, 10, 60, reflector),
      inject: [RateLimiterService, Reflector],
    },
  ],

  exports: [
    UserService,
    AuthService,
    RoleService,
    PermissionService,
    AuthTokenService,
    JwtModule,
    JwtAuthGuard,
  ],
})
export class UserManagementModule {}
