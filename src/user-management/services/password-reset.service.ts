import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { PasswordReset } from 'src/user-management/entities/password-reset.entity';
import { UserQueryService } from 'src/user-management/services/user-query/user-query.service';
import { UserCommandService } from 'src/user-management/services/user-command/user-command.service';
import { PasswordResetTokenService } from './password-reset-token.service';
import { hashPassword } from 'src/user-management/utils/password.util';

@Injectable()
export class PasswordResetService {
  constructor(
    @InjectRepository(PasswordReset)
    private passwordResetRepository: Repository<PasswordReset>,
    private userQueryService: UserQueryService,
    private userCommandService: UserCommandService,
    private passwordResetTokenService: PasswordResetTokenService,
  ) {}

  async createPasswordReset(email: string): Promise<{ token: string }> {
    const user = await this.userQueryService.findUserByEmail(email);
    
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Clean up expired tokens
    await this.passwordResetRepository.delete({
      expiresAt: LessThan(new Date()),
    });

    const token = this.passwordResetTokenService.generateToken();
    const expiresAt = this.passwordResetTokenService.generateExpirationDate();

    const passwordReset = this.passwordResetRepository.create({
      token,
      userId: user.id,
      expiresAt,
    });

    await this.passwordResetRepository.save(passwordReset);

    return { token };
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const passwordReset = await this.passwordResetRepository.findOne({
      where: {
        token,
        used: false,
        expiresAt: LessThan(new Date()),
      },
    });

    if (!passwordReset) {
      throw new UnauthorizedException('Invalid or expired token');
    }

    const hashedPassword = await hashPassword(newPassword);
    await this.userCommandService.updateUser(passwordReset.userId, {
      password: hashedPassword,
    });

    // Mark token as used
    passwordReset.used = true;
    await this.passwordResetRepository.save(passwordReset);
  }
}