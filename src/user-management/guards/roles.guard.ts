import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RolePermissions } from '../roles-permissions/role-permissions.map';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { GqlExecutionContext } from '@nestjs/graphql';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<string[]>(
      ROLES_KEY,
      context.getHandler(),
    );
    const requiredPermissions = this.reflector.get<string[]>(
      PERMISSIONS_KEY,
      context.getHandler(),
    );

    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;
    const user = req.user;

    if (!user || !user.role) {
      throw new ForbiddenException('Role not authorized');
    }

    const hasRole = requiredRoles?.some(
      (roleName) => roleName === user.role.name,
    );

    if (requiredRoles && !hasRole) {
      throw new ForbiddenException('Role not authorized');
    }

    const userPermissions = RolePermissions[user.role.name] || [];

    if (requiredPermissions) {
      const hasPermission = requiredPermissions.every((perm) =>
        userPermissions.includes(perm),
      );
      if (!hasPermission) {
        throw new ForbiddenException('Role not authorized');
      }
    }

    return true;
  }
}
