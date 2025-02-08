import { Injectable } from '@nestjs/common';
import { UserQueryService } from 'src/user-management/services/user-query/user-query.service';
import { comparePasswords } from 'src/user-management/utils/password.util';
import { AuthenticationError } from 'src/user-management/utils/error.util';

@Injectable()
export class AuthValidationService {
  constructor(private userQueryService: UserQueryService) {}

  async validateUserCredentials(email: string, password: string): Promise<any> {
    try {
      const user = await this.userQueryService.findUserByEmail(email);
      
      if (!user) {
        throw new AuthenticationError('User not found');
      }

      if (!user.password) {
        throw new AuthenticationError('Invalid user credentials');
      }

      const isPasswordValid = await comparePasswords(password, user.password);
      
      if (!isPasswordValid) {
        throw new AuthenticationError('Invalid password');
      }

      const { password: _, ...result } = user;
      return result;
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new AuthenticationError('Error validating user credentials');
    }
  }

  async validatePasswordChange(userId: string, currentPassword: string): Promise<any> {
    try {
      const user = await this.userQueryService.findUserById(userId);
      
      if (!user || !user.password) {
        throw new AuthenticationError('User not found or invalid credentials');
      }

      const isPasswordValid = await comparePasswords(currentPassword, user.password);
      
      if (!isPasswordValid) {
        throw new AuthenticationError('Current password is incorrect');
      }

      return user;
    } catch (error) {
      if (error instanceof AuthenticationError) {
        throw error;
      }
      throw new AuthenticationError('Error validating password change');
    }
  }
}