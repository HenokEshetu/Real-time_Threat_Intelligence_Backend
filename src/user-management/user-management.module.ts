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
import { AuthService } from './services/auth/auth.service';
import { UserQueryService } from './services/user-query.service';
import { UserCommandService } from './services/user-command.service';
import { AuthValidationService } from './services/auth/auth-validation.service';
import { AuthTokenService } from './services/auth/auth-token.service';
import { PasswordResetService } from './services/password-reset.service';
import { PasswordResetTokenService } from './services/password-reset-token.service';
import { TokenBlacklistService } from './services/auth/token-blacklist.service';
import { AuthSessionService } from './services/auth/auth-session.service';

import { UserResolver } from './resolvers/user.resolver';
import { AuthResolver } from './resolvers/auth.resolver';
import { PasswordResetResolver } from './resolvers/password-reset.resolver';

import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { GoogleStrategy } from './strategies/google.strategy';

import databaseConfig from '../config/database.config';
import authConfig from '../config/auth.config';
import { EmailVerificationToken } from './entities/email-verification-token.entity';
import { EmailVerificationService } from './services/email-verification.service';
import emailConfig from 'src/config/email.config';
import { MailerModule } from '@nestjs-modules/mailer';
import { join } from 'path';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { EmailVerificationResolver } from './resolvers/email-verification.resolver';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, authConfig, emailConfig],
    }),

    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        ...configService.get('database'),
        autoLoadEntities: true,
      }),
    }),

    TypeOrmModule.forFeature([
      User,
      Role,
      Permission,
      PasswordReset,
      EmailVerificationToken,
    ]),

    PassportModule.register({ defaultStrategy: 'jwt' }),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('AUTH_JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('AUTH_JWT_EXPIRES_IN') || '15m',
        },
      }),
    }),

    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('AUTH_JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('AUTH_JWT_REFRESH_IN') || '1d',
        },
      }),
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

    JwtStrategy,
    LocalStrategy,
    GoogleStrategy,

    EmailVerificationService,
  ],

  exports: [
    UserService,
    AuthService,
    RoleService,
    PermissionService,
    AuthTokenService,
    JwtModule,
  ],
})
export class UserManagementModule {}
