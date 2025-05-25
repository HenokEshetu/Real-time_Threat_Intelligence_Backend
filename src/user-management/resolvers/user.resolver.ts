import { Resolver, Query, Mutation, Args, ID } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { UserService } from 'src/user-management/services/user.service';
import { User } from 'src/user-management/entities/user.entity';
import { CreateUserDto } from 'src/user-management/dto/create-user.dto';
import { UpdateUserDto } from 'src/user-management/dto/update-user.dto';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Roles } from 'src/user-management/decorators/roles.decorator';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { PermissionsGuard } from 'src/user-management/guards/permissions.guard';
import { Public } from '../decorators/public.decorator';

@Resolver(() => User)
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  @Query(() => [User])


  async users(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Query(() => User)
  // @UseGuards(PermissionsGuard)
  // @Permissions('VIEW_USER')
  async user(@Args('id', { type: () => ID }) id: string): Promise<User> {
    return this.userService.findOne(id);
  }
  
  @Mutation(() => User)
  // @UseGuards(PermissionsGuard)
  // @Permissions('CREATE_USER')
  @Public()
  async createUser(@Args('createUserInput') createUserDto: CreateUserDto): Promise<User> {
    return this.userService.create(createUserDto);
  }

  @Mutation(() => User)
  // @UseGuards(PermissionsGuard)
  // @Permissions('UPDATE_USER')
  async updateUser(
    @Args('id', { type: () => ID }) id: string,
    @Args('updateUserInput') updateUserDto: UpdateUserDto,
  ): Promise<User> {
    return this.userService.update(id, updateUserDto);
  }

  @Mutation(() => Boolean)
  @UseGuards(RolesGuard)
  @Roles('ADMIN')
  async removeUser(@Args('id', { type: () => ID }) id: string): Promise<boolean> {
    await this.userService.remove(id);
    return true;
  }
}
