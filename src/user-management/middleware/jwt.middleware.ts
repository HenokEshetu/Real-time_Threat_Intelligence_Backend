import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { JwtService } from '@nestjs/jwt';
import { UserService } from '../services/user.service';

@Injectable()
export class JwtMiddleware implements NestMiddleware {
  constructor(
    private jwtService: JwtService,
    private userService: UserService,
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      try {
        const payload = this.jwtService.verify(token);
        req['user'] = await this.userService.findOne(payload.sub);
      } catch (error) {
        // Throw a structured error to be handled by global filters
        throw new UnauthorizedException({
          message: 'Invalid or expired token',
          code: 'UNAUTHENTICATED',
        });
      }
    }
    next();
  }
}