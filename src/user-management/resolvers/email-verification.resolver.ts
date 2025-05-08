import { Resolver, Mutation, Args } from '@nestjs/graphql';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { EmailVerificationService } from '../services/email-verification.service';
import { AuthResponse } from '../types/auth.types';
import { SkipVerified } from '../decorators/skip-verified.decorator';
import { User } from '../entities/user.entity';

@Resolver()
export class EmailVerificationResolver {
  constructor(
    private readonly emailVerificationService: EmailVerificationService,
  ) {}

  @Mutation(() => User)
  @SkipVerified()
  async verifyEmail(
    @Args('token', { type: () => String }) token: string,
  ): Promise<User> {
    try {
      return await this.emailVerificationService.verifyEmail(token);
    } catch (error) {
      throw error;
    }
  }
}
