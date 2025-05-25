import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';
import { SKIP_CSRF_KEY } from './skip-csrf.decorator';
import { IS_PUBLIC_KEY } from 'src/user-management/decorators/public.decorator';

@Injectable()
export class CsrfGuard implements CanActivate {
  private csrf = csurf({
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    },
    value: (req) => req.headers['x-csrf-token'] as string,
  });

  constructor(private reflector: Reflector) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const skip = this.reflector.getAllAndOverride<boolean>(SKIP_CSRF_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (skip) return true;

    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const gqlCtx = GqlExecutionContext.create(context);
    const { req, res } = gqlCtx.getContext();

    const body = req.body;
    const queries = Array.isArray(body) ? body : [body];

    const needsProtection = queries.some(
      (q) =>
        typeof q.query === 'string' &&
        /^\s*(mutation|subscription)\s/i.test(q.query),
    );

    if (!needsProtection) return true;

    return new Promise<boolean>((resolve, reject) => {
      cookieParser()(req, res, () => {
        this.csrf(req, res, (err) => {
          if (err) {
            return reject(new ForbiddenException('Invalid CSRF token'));
          }
          res.cookie('XSRF-TOKEN', req.csrfToken(), {
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            httpOnly: false,
          });
          resolve(true);
        });
      });
    });
  }
}
