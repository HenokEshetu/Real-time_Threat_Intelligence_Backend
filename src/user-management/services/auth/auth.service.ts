import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user-management/services/user.service';
import { LoginDto } from 'src/user-management/dto/login.dto';
import { ChangePasswordDto } from 'src/user-management/dto/change-password.dto';
import { LoginResponse } from 'src/user-management/types/auth.types';
import { comparePasswords } from 'src/user-management/utils/password.util';
import { createTokenPayload, generateToken } from 'src/user-management/utils/token.util';
import { AuthenticationError } from '../../utils/error.util';
import { SignOutDto } from 'src/user-management/dto/sign-out.dto';
import { AuthSessionService } from './auth-session.service';
import { User } from 'src/user-management/entities/user.entity';

@Injectable()
export class AuthService {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private authSessionService: AuthSessionService,
  ) {}

  async validateUser(email: string, password: string): Promise<User> {
    try {
      const user = await this.userService.findByEmail(email);
      if (!user) {
        return null;
      }

      const isPasswordValid = await comparePasswords(password, user.password);
      if (!isPasswordValid) {
        return null;
      }

      return user;
    } catch (error) {
      console.error('Error validating user:', error);
      return null;
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    try {
      const user = await this.validateUser(loginDto.email, loginDto.password);
      if (!user) {
        throw new UnauthorizedException('Invalid email or password');
      }

      const payload = createTokenPayload(user);
      const access_token = generateToken(this.jwtService, payload);

      console.log()

      return {
        access_token,
        user,
      };
    } catch (error) {
      console.error('Login error:', error);
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('An error occurred during login');
    }
  }

  async signOut(token: SignOutDto): Promise<void> {
    if (!token) {
      throw new AuthenticationError('Token is required');
    }

    await this.authSessionService.signOut(token);
  }


  async changePassword(userId: string, changePasswordDto: ChangePasswordDto): Promise<void> {
    try {
      const user = await this.userService.findOne(userId);
      const isPasswordValid = await comparePasswords(
        changePasswordDto.oldPassword,
        user.password,
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('Current password is incorrect');
      }

      const hashedPassword = changePasswordDto.newPassword;
      await this.userService.update(userId, { password: hashedPassword });
    } catch (error) {
      console.error('Change password error:', error);
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('An error occurred while changing password');
    }
  }
}



