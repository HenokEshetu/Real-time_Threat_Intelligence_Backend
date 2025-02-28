import { Logger } from '@nestjs/common';
import {
  StixValidationError,
  StixParsingError,
  StixVersionError,
  StixIdentifierError,
  StixRelationshipError,
  StixMarkingError,
  StixPatternError,
} from './custom-exceptions';

export class StixErrorHandler {
  private static readonly logger = new Logger('StixErrorHandler');

  static handleValidationError(error: Error, context: string): never {
    this.logger.error(`Validation error in ${context}: ${error.message}`);
    throw new StixValidationError(error.message);
  }

  static handleParsingError(error: Error, context: string): never {
    this.logger.error(`Parsing error in ${context}: ${error.message}`);
    throw new StixParsingError(error.message);
  }

  static handleVersionError(error: Error, context: string): never {
    this.logger.error(`Version error in ${context}: ${error.message}`);
    throw new StixVersionError(error.message);
  }

  static handleIdentifierError(error: Error, context: string): never {
    this.logger.error(`Identifier error in ${context}: ${error.message}`);
    throw new StixIdentifierError(error.message);
  }

  static handleRelationshipError(error: Error, context: string): never {
    this.logger.error(`Relationship error in ${context}: ${error.message}`);
    throw new StixRelationshipError(error.message);
  }

  static handleMarkingError(error: Error, context: string): never {
    this.logger.error(`Marking error in ${context}: ${error.message}`);
    throw new StixMarkingError(error.message);
  }

  static handlePatternError(error: Error, context: string): never {
    this.logger.error(`Pattern error in ${context}: ${error.message}`);
    throw new StixPatternError(error.message);
  }

  static handleGenericError(error: Error, context: string): never {
    this.logger.error(`Generic error in ${context}: ${error.message}`);
    throw error;
  }
}