import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';
import { Permission } from './entities/permission.entity';
import { UserService } from 'src/user-management/services/user/user.service';
import { AuthService } from 'src/user-management/services/auth/auth.service';
import { UserResolver } from 'src/user-management/resolvers/user/user.resolver';
import { AuthResolver } from 'src/user-management/resolvers/auth/auth.resolver';
import { JwtStrategy } from './strategies/jwt.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { RoleService } from 'src/user-management/services/role/role.service';
import { PermissionService } from 'src/user-management/services/permission/permission.service';
import { UserQueryService } from 'src/user-management/services/user-query/user-query.service';
import { UserCommandService } from 'src/user-management/services/user-command/user-command.service';
import { AuthValidationService } from 'src/user-management/services/auth/auth-validation/auth-validation.service';
import { AuthTokenService } from 'src/user-management/services/auth/auth-token/auth-token.service';

import { PasswordReset } from './entities/password-reset.entity';

import { PasswordResetService } from 'src/user-management/services/password-reset.service';
import { PasswordResetTokenService } from 'src/user-management/services/password-reset-token.service';
import { PasswordResetResolver } from './resolvers/password-reset.resolver';



@Module({
  imports: [
    TypeOrmModule.forFeature([User, Role, Permission, PasswordReset]),
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('auth.jwtSecret'),
        signOptions: { expiresIn: configService.get('auth.jwtExpiresIn') },
      }),
    }),
  ],
  providers: [
    UserService,
    UserQueryService,
    UserCommandService,
    AuthService,
    AuthValidationService,
    AuthTokenService,
    PasswordResetService,
    PasswordResetTokenService,
    RoleService,
    PermissionService,
    UserResolver,
    AuthResolver,
    PasswordResetResolver,
    JwtStrategy,
    LocalStrategy,
    GoogleStrategy,
  ],
  exports: [
    UserService,
    AuthService,
    RoleService,
    PermissionService,
    PasswordResetService,
  ],
})
export class UserManagementModule {}