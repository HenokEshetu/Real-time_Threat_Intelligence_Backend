import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  Logger,
  HttpStatus,
} from '@nestjs/common';
import { RateLimiterService } from './rate-limitter.service';
import { Reflector } from '@nestjs/core';
import { SKIP_RATE_LIMITING_KEY } from 'src/security/skip-rate-limmiting.decorator';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class RateLimiterGuard implements CanActivate {
  constructor(
    private rateLimiterService: RateLimiterService,
    private limit: number,
    private windowSeconds: number,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    let request: any = context.switchToHttp().getRequest();
    if (!request) {
      const gqlCtx = GqlExecutionContext.create(context);
      request = gqlCtx.getContext().req;
    }
    const identifier = request?.ip || 'unknown';

    const skip = this.reflector.getAllAndOverride<boolean>(
      SKIP_RATE_LIMITING_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (skip) return true;

    const result = await this.rateLimiterService.checkRateLimit(
      identifier,
      this.limit,
      this.windowSeconds,
    );

    if (!result.allowed) {
      Logger.warn(
        `Rate limit hit for ${identifier}, retry in ${result.remaining}s`,
      );

      const exception = new HttpException(
        { message: 'Too many requests. Please try again later.' },
        HttpStatus.TOO_MANY_REQUESTS,
      );

      // Attach Retry-After header for HTTP clients
      exception.getResponse()['headers'] = {
        'Retry-After': result.remaining.toString(),
      };

      throw exception;
    }

    return true;
  }
}
