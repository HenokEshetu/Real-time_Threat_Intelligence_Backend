import { UnauthorizedException } from '@nestjs/common';

export class AuthenticationError extends UnauthorizedException {
  constructor(message: string = 'Authentication failed') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export const handleAuthError = (error: any): never => {
  console.error('Authentication error:', error);
  
  if (error instanceof UnauthorizedException) {
    throw error;
  }
  
  throw new AuthenticationError('An unexpected error occurred during authentication');
};