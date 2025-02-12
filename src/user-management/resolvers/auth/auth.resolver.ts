import { Resolver, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { AuthService } from 'src/user-management/services/auth/auth.service';
import { AuthSessionService } from 'src/user-management/services/auth/auth-session.service';
import { LoginDto } from 'src/user-management/dto/login.dto';
import { ChangePasswordDto } from 'src/user-management/dto/change-password.dto';
import { JwtAuthGuard } from 'src/user-management/guards/jwt-auth.guard';
import { SignOutDto } from 'src/user-management/dto/sign-out.dto';
import { LoginResponse, AuthResponse } from 'src/user-management/types/auth.types';

@Resolver()
export class AuthResolver {
  constructor(private readonly authService: AuthService,
    private readonly authSessionService: AuthSessionService 
  ) {}
 

  @Mutation(() => LoginResponse)
  async login(
    @Args('input') loginDto: LoginDto
  ): Promise<LoginResponse> {
    return this.authService.login(loginDto);
  }
  
  @Mutation(() => AuthResponse)
  @UseGuards(JwtAuthGuard)
  async signOut(
    @Args('input') signOutDto: SignOutDto,
    @Context() context,
  ): Promise<AuthResponse> {
    const token = context.req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      throw new Error('No authentication token provided');
    }

    await this.authService.signOut(token);
    return {
      success: true,
      message: 'Successfully signed out',
    };
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



  