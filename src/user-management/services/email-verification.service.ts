import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { EmailVerificationToken } from '../entities/email-verification-token.entity';
import { User } from '../entities/user.entity';
import { generateVerificationToken } from '../utils/email-verification.util';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailVerificationService {
  constructor(
    @InjectRepository(EmailVerificationToken)
    private emailVerificationTokenRepository: Repository<EmailVerificationToken>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private mailerService: MailerService,
    private configService: ConfigService,
  ) {}

  async createVerificationToken(user: User): Promise<string> {
    const token = generateVerificationToken();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 5); // Token expires in 5 minutes

    const emailVerificationToken = this.emailVerificationTokenRepository.create({
      token,
      user,
      expiresAt,
    });

    await this.emailVerificationTokenRepository.save(emailVerificationToken);
    return token;
  }

  async verifyEmail(token: string): Promise<User> {
    const emailVerificationToken = await this.emailVerificationTokenRepository.findOne({
      where: { token },
      relations: ['user', 'user.roles', 'user.roles.permissions'],
    });

    if (!emailVerificationToken) {
      throw new NotFoundException('Invalid or expired verification token');
    }

    if (emailVerificationToken.expiresAt < new Date()) {
      throw new BadRequestException('Verification token has expired');
    }

    const user = emailVerificationToken.user;
    user.isEmailVerified = true;
    await this.userRepository.save(user);

    await this.emailVerificationTokenRepository.delete(emailVerificationToken.id);

    return this.userRepository.findOneOrFail({
      where: { userId: user.userId },
      relations: ['roles', 'roles.permissions'],
    });
  }

  async sendVerificationEmail(user: User, token: string): Promise<void> {
    const verificationUrl = `http://localhost:5173/auth/verify-email/${token}`;
    await this.mailerService.sendMail({
      from: this.configService.get<string>('email.from'),
      to: user.email,
      subject: 'Email Verification',
      template: 'email-verification',
      context: {
        name: user.firstName,
        verificationUrl,
      },
    });
  }
}
