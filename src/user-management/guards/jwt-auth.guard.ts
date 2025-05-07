import { Injectable, ExecutionContext, Logger, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { SKIP_VERIFIED_KEY } from '../decorators/skip-verified.decorator';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(private reflector: Reflector) {
    super();
  }

  canActivate(context: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const skip = this.reflector.getAllAndOverride<boolean>(
      SKIP_VERIFIED_KEY,
      [
        context.getHandler(),
        context.getClass(),
      ],
    );
    if (skip) {
      return true;
    }

    return super.canActivate(context);
  }

  getRequest(context: ExecutionContext): Request {
    try {
      const ctx = GqlExecutionContext.create(context);
      const { req } = ctx.getContext();

      if (!req) {
        return context.switchToHttp().getRequest();
      }

      return req;
    } catch (error) {
      this.logger.error('Error extracting request from context', error.stack);
      throw new UnauthorizedException('Authentication context error');
    }
  }

  handleRequest<TUser = any>(err: any, user: any, info: any, context: ExecutionContext): TUser {
    if (err || !user) {
      this.logger.warn(`Authentication failed: ${err?.message || info?.message}`);
      throw err || new UnauthorizedException('Invalid or expired token');
    }

    if (context.getType<string>() === 'graphql') {
      const ctx = GqlExecutionContext.create(context);
      ctx.getContext().user = user;
    }

    return user;
  }
}
