import { HttpException, HttpStatus } from '@nestjs/common';

export class StixValidationError extends HttpException {
  constructor(message: string) {
    super({
      status: HttpStatus.BAD_REQUEST,
      error: 'STIX Validation Error',
      message,
    }, HttpStatus.BAD_REQUEST);
  }
}

export class StixParsingError extends HttpException {
  constructor(message: string) {
    super({
      status: HttpStatus.BAD_REQUEST,
      error: 'STIX Parsing Error',
      message,
    }, HttpStatus.BAD_REQUEST);
  }
}

export class StixVersionError extends HttpException {
  constructor(message: string) {
    super({
      status: HttpStatus.BAD_REQUEST,
      error: 'STIX Version Error',
      message,
    }, HttpStatus.BAD_REQUEST);
  }
}

export class StixIdentifierError extends HttpException {
  constructor(message: string) {
    super({
      status: HttpStatus.BAD_REQUEST,
      error: 'STIX Identifier Error',
      message,
    }, HttpStatus.BAD_REQUEST);
  }
}

export class StixRelationshipError extends HttpException {
  constructor(message: string) {
    super({
      status: HttpStatus.BAD_REQUEST,
      error: 'STIX Relationship Error',
      message,
    }, HttpStatus.BAD_REQUEST);
  }
}

export class StixMarkingError extends HttpException {
  constructor(message: string) {
    super({
      status: HttpStatus.FORBIDDEN,
      error: 'STIX Marking Error',
      message,
    }, HttpStatus.FORBIDDEN);
  }
}

export class StixPatternError extends HttpException {
  constructor(message: string) {
    super({
      status: HttpStatus.BAD_REQUEST,
      error: 'STIX Pattern Error',
      message,
    }, HttpStatus.BAD_REQUEST);
  }
}