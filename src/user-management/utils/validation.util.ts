import { ValidationError } from '@nestjs/common';

export const formatValidationErrors = (errors: ValidationError[]): string[] => {
  const messages: string[] = [];
  
  errors.forEach(error => {
    if (error.constraints) {
      Object.values(error.constraints).forEach(message => {
        messages.push(message);
      });
    }
    
    if (error.children?.length) {
      messages.push(...formatValidationErrors(error.children));
    }
  });
  
  return messages;
};

export const validatePassword = (password: string): boolean => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return (
    password.length >= minLength &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumbers &&
    hasSpecialChar
  );
};