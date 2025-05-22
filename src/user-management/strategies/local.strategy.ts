import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from 'src/user-management/services/auth/auth.service';
import { AuthValidationService } from '../services/auth/auth-validation.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authValidationService: AuthValidationService) {
    super({ usernameField: 'email' });
  }

  async validate(email: string, password: string): Promise<any> {
    const user = await this.authValidationService.validateUserCredentials(
      email,
      password,
    );
    if (!user) {
      throw new UnauthorizedException();
    }
    return user;
  }
}
