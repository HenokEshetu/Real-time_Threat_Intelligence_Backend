import { Resolver, Mutation, Args } from '@nestjs/graphql';
import { EmailVerificationService } from '../services/email-verification.service';
import { User } from '../entities/user.entity';
import { Public } from '../decorators/public.decorator';

@Resolver()
export class EmailVerificationResolver {
  constructor(
    private readonly emailVerificationService: EmailVerificationService,
  ) {}

  @Mutation(() => User)
  @Public()
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
