import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import csurf from 'csurf';
import cookieParser from 'cookie-parser';

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private csrf = csurf({
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    },
    value: (req: Request) => req.headers['x-csrf-token'] as string,
  });

  use(req: Request, res: Response, next: NextFunction) {
    cookieParser()(req, res, () => {
      const isGraphQLMutation = this.isGraphQLMutation(req);

      if (!isGraphQLMutation) {
        return next();
      }

      this.csrf(req, res, (err) => {
        if (err) return this.handleError(err, res);

        // Send CSRF token as readable cookie for frontend (e.g., SPA)
        res.cookie('XSRF-TOKEN', req.csrfToken(), {
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          httpOnly: false,
        });
        next();
      });
    });
  }

  private isGraphQLMutation(req: Request): boolean {
    if (req.method !== 'POST' || req.path !== '/graphql') return false;

    const body = req.body;
    const queries = Array.isArray(body) ? body : [body];

    return queries.some(
      (q) => typeof q.query === 'string' && /^\s*mutation\s/i.test(q.query),
    );
  }

  private handleError(err: any, res: Response) {
    res.status(403).json({
      message: 'Invalid CSRF token',
      code: 'INVALID_CSRF_TOKEN',
    });
  }
}
