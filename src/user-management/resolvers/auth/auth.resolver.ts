import { Resolver, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { AuthService } from 'src/user-management/services/auth/auth.service';
import { LoginDto } from 'src/user-management/dto/login.dto';
import { ChangePasswordDto } from 'src/user-management/dto/change-password.dto';
import { JwtAuthGuard } from 'src/user-management/guards/jwt-auth.guard';

import { LoginResponse, AuthResponse } from 'src/user-management/types/auth.types';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Mutation(() => LoginResponse)
  async login(
    @Args('input') loginDto: LoginDto
  ): Promise<LoginResponse> {
    return this.authService.login(loginDto);
  }

  @Mutation(() => AuthResponse)
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @Args('input') changePasswordDto: ChangePasswordDto,
    @Context() context,
  ): Promise<AuthResponse> {
    await this.authService.changePassword(context.req.user.id, changePasswordDto);
    return {
      success: true,
      message: 'Password changed successfully',
    };
  }
}