//gql-exception.filter.ts
import { Catch, ArgumentsHost } from '@nestjs/common';
import { GqlExceptionFilter } from '@nestjs/graphql';
import { UnauthorizedException } from '@nestjs/common';
@Catch(UnauthorizedException)
export class UnauthorizedExceptionFilter implements GqlExceptionFilter {
  catch(exception: UnauthorizedException, host: ArgumentsHost) {
    // Extract the original error message
    const errorResponse = exception.getResponse();
    const message = typeof errorResponse === 'object' 
      ? (errorResponse as { message: string }).message 
      : exception.message;

    // Return a simplified GraphQL error
    return {
      message,
      extensions: {
        code: 'UNAUTHENTICATED',
      },
    };
  }
}