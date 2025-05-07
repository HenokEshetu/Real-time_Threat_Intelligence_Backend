// permissions.guard.ts
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { GqlExecutionContext } from '@nestjs/graphql';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.get<string[]>(
      PERMISSIONS_KEY,
      context.getHandler()
    );

    if (!requiredPermissions?.length) return true;

    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req || context.switchToHttp().getRequest();
    const user = req.user;

    if (!user?.roles) return false;

    const userPermissions = user.roles
      .flatMap(role => role.permissions?.map(p => p.name) || [])
      .filter(Boolean);

    return requiredPermissions.some(perm =>
      userPermissions.includes(perm)
    );
  }
}
