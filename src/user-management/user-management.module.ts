import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';

import { Permission } from './entities/permission.entity';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';

import { PasswordReset } from './entities/password-reset.entity';

// Services
import { UserService } from './services/user/user.service';
import { RoleService } from './services/role/role.service';
import { PermissionService } from './services/permission/permission.service';
import { AuthService } from './services/auth/auth.service';
import { UserQueryService } from './services/user-query/user-query.service';
import { UserCommandService } from './services/user-command/user-command.service';
import { AuthValidationService } from './services/auth/auth-validation/auth-validation.service';
import { AuthTokenService } from './services/auth/auth-token/auth-token.service';
import { PasswordResetService } from './services/password-reset.service';
import { PasswordResetTokenService } from './services/password-reset-token.service';
import { TokenBlacklistService } from './services/auth/auth-token/token-blacklist.service';
import { AuthSessionService } from './services/auth/auth-session.service';

// Resolvers
import { UserResolver } from './resolvers/user/user.resolver';
import { AuthResolver } from './resolvers/auth/auth.resolver';
import { PasswordResetResolver } from './resolvers/password-reset.resolver';

// Strategies
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { GoogleStrategy } from './strategies/google.strategy';

import databaseConfig from '../config/database.config';
import authConfig from '../config/auth.config';
@Module({
  imports: [
    // Global Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, authConfig],
    }),

    // PostgreSQL Connection (User Management)
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        ...configService.get('database'),
        autoLoadEntities: true,
      }),
    }),

    TypeOrmModule.forFeature([User, Role, Permission, PasswordReset]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('AUTH_JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('AUTH_JWT_EXPIRES_IN') || '1h',
        },
      }),
    }),
  ],
  providers: [
    // Core Services
    UserService,
    AuthService,
    RoleService,
    PermissionService,
    AuthSessionService,

    // Authentication
    AuthValidationService,
    AuthTokenService,
    TokenBlacklistService,

    // Query & Command Services
    UserQueryService,
    UserCommandService,

    // Password Reset
    PasswordResetService,
    PasswordResetTokenService,

    // GraphQL Resolvers
    UserResolver,
    AuthResolver,
    PasswordResetResolver,

    // Strategies
    JwtStrategy,
    LocalStrategy,
    GoogleStrategy,
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
