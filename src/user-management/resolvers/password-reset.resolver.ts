import { Resolver, Mutation, Args } from '@nestjs/graphql';
import { ResetPasswordDto } from 'src/user-management/dto/reset-password.dto';
import { forgotPasswordDto } from 'src/user-management/dto/forgot-passwordDTO.dto';

import { PasswordResetService } from 'src/user-management/services/password-reset.service';
import { AuthResponse } from '../types/auth.types';

@Resolver()
export class PasswordResetResolver {
  constructor(private readonly passwordResetService: PasswordResetService) {}

  @Mutation(() => AuthResponse)
  async forgotPassword(
    @Args('input') ForgotPasswordDto: forgotPasswordDto,
  ): Promise<AuthResponse> {
    await this.passwordResetService.createPasswordReset(ForgotPasswordDto.email);
    return {
      success: true,
      message: 'If an account exists with that email, a password reset link will be sent',
    };
  }

  @Mutation(() => AuthResponse)
  async resetPassword(
    @Args('input') resetPasswordDto: ResetPasswordDto,
  ): Promise<AuthResponse> {
    await this.passwordResetService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.newPassword,
    );
    return {
      success: true,
      message: 'Password has been reset successfully',
    };
  }
}