import { Resolver, Query, Mutation, Args, ID, Context } from '@nestjs/graphql';
import {
  ForbiddenException,
  NotFoundException,
  UseGuards,
} from '@nestjs/common';
import { UserService } from 'src/user-management/services/user.service';
import { User } from 'src/user-management/entities/user.entity';
import { CreateUserDto } from 'src/user-management/dto/create-user.dto';
import { UpdateUserDto } from 'src/user-management/dto/update-user.dto';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Roles } from 'src/user-management/decorators/roles.decorator';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';
import { Roles as roles } from 'src/user-management/roles-permissions/role.enum';
import { CreateUserGuard } from '../guards/create-user.guard';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';

interface GqlContext {
  req: {
    user: {
      sub: string;
      role: roles;
    };
  };
}

@Resolver(() => User)
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  @UseGuards(RolesGuard)
  @Roles(roles.Administrator)
  @Permissions(permissions.Account.ViewAll)
  @Query(() => [User])
  async users(): Promise<User[]> {
    return this.userService.findAll();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.Account.ViewOwn)
  @Query(() => User)
  async user(
    @Args('id', { type: () => ID }) id: string,
    @Context() { req }: GqlContext,
  ): Promise<User> {
    const { sub: requesterId, role } = req.user;

    if (role !== roles.Administrator && requesterId !== id) {
      throw new ForbiddenException('Role not authorized');
    }

    const user = await this.userService.findOne(id);
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  @UseGuards(CreateUserGuard)
  @Mutation(() => User)
  async createUser(
    @Args('createUserInput') createUserDto: CreateUserDto,
  ): Promise<User> {
    return this.userService.create(createUserDto);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.Account.UpdateOwn)
  @Mutation(() => User)
  async updateUser(
    @Args('id', { type: () => ID }) id: string,
    @Args('updateUserInput') updateUserDto: UpdateUserDto,
    @Context() { req }: GqlContext,
  ): Promise<User> {
    const { sub: requesterId } = req.user;

    if (requesterId !== id) {
      throw new ForbiddenException('Role not authorized');
    }

    return this.userService.update(id, updateUserDto);
  }

  @UseGuards(RolesGuard)
  @Roles(roles.User)
  @Mutation(() => Boolean)
  async requestAccountDeletion(
    @Context() { req }: GqlContext,
  ): Promise<boolean> {
    const userId = req.user.sub;
    await this.userService.requestDeletion(userId);
    return true;
  }

  @UseGuards(RolesGuard)
  @Roles(roles.Administrator)
  @Mutation(() => Boolean)
  async approveAccountDeletion(
    @Args('userId') userId: string,
  ): Promise<boolean> {
    await this.userService.approveDeletion(userId);
    return true;
  }
}
