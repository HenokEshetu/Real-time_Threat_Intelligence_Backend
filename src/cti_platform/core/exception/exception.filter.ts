import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    HttpStatus,
    Logger,
  } from '@nestjs/common';
  import { GqlArgumentsHost } from '@nestjs/graphql';
  import {
    StixValidationError,
    StixParsingError,
    StixVersionError,
    StixIdentifierError,
    StixRelationshipError,
    StixMarkingError,
    StixPatternError,
  } from './custom-exceptions';
  
  @Catch()
  export class StixExceptionFilter implements ExceptionFilter {
    private readonly logger = new Logger('StixExceptionFilter');
  
    catch(exception: unknown, host: ArgumentsHost) {
      const gqlHost = GqlArgumentsHost.create(host);
      const context = gqlHost.getContext();
  
      let status = HttpStatus.INTERNAL_SERVER_ERROR;
      let message = 'Internal server error';
      let error = 'Internal Server Error';
  
      if (exception instanceof HttpException) {
        const response = exception.getResponse() as any;
        status = exception.getStatus();
        message = response.message || response;
        error = response.error || 'Error';
      }
  
      // Log the error with appropriate severity based on the exception type
      if (
        exception instanceof StixValidationError ||
        exception instanceof StixParsingError ||
        exception instanceof StixVersionError ||
        exception instanceof StixIdentifierError ||
        exception instanceof StixPatternError
      ) {
        this.logger.warn(`STIX Error: ${message}`);
      } else if (
        exception instanceof StixMarkingError ||
        exception instanceof StixRelationshipError
      ) {
        this.logger.error(`STIX Security Error: ${message}`);
      } else {
        this.logger.error(`Unhandled Exception: ${message}`);
        if (exception instanceof Error) {
          this.logger.error(exception.stack);
        }
      }
  
      // For GraphQL responses
      if (context.req) {
        return {
          status,
          error,
          message,
        };
      }
  
      // For REST responses
      const response = host.switchToHttp().getResponse();
      response.status(status).json({
        status,
        error,
        message,
      });
    }
  }