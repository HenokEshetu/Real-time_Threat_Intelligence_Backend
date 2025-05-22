import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { JwtService } from '@nestjs/jwt';
import { Roles } from '../roles-permissions/role.enum';

@Injectable()
export class CreateUserGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(execCtx: ExecutionContext): Promise<boolean> {
    const gqlCtx = GqlExecutionContext.create(execCtx).getContext<{ req }>();
    const { headers, args } = gqlCtx.req;
    const createUserInput = args.createUserInput as { role?: Roles };

    if (!headers.authorization) {
      createUserInput.role = Roles.User;
      return true;
    }

    const token = headers.authorization.replace(/^Bearer\s+/, '');
    let payload: any;
    try {
      payload = await this.jwtService.verifyAsync(token);
    } catch {
      createUserInput.role = Roles.User;
      return true;
    }

    if (payload.roles !== Roles.Administrator) {
      createUserInput.role = Roles.User;
      return true;
    }

    createUserInput.role = createUserInput.role ?? Roles.User;
    return true;
  }
}
