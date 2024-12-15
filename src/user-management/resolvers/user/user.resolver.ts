import { Resolver, Query, Mutation, Args, ID } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { UserService } from 'src/user-management/services/user/user.service';
import { User } from 'src/user-management/entities/user.entity';
import { CreateUserDto } from 'src/user-management/dto/create-user.dto';
import { UpdateUserDto } from 'src/user-management/dto/update-user.dto';
import { JwtAuthGuard } from 'src/user-management/guards/jwt-auth.guard';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Roles } from 'src/user-management/decorators/roles/roles.decorator';

@Resolver(() => User)
export class UserResolver {
  constructor(private readonly userService: UserService) {}

  @Query(() => [User])
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  async users(): Promise<User[]> {
    return this.userService.findAll();
  }

  @Query(() => User)
  @UseGuards(JwtAuthGuard)
  async user(@Args('id', { type: () => ID }) id: string): Promise<User> {
    return this.userService.findOne(id);
  }

  @Mutation(() => User)
  async createUser(@Args('createUserInput') createUserDto: CreateUserDto): Promise<User> {
    return this.userService.create(createUserDto);
  }

  @Mutation(() => User)
  @UseGuards(JwtAuthGuard)
  async updateUser(
    @Args('id', { type: () => ID }) id: string,
    @Args('updateUserInput') updateUserDto: UpdateUserDto,
  ): Promise<User> {
    return this.userService.update(id, updateUserDto);
  }

  @Mutation(() => Boolean)
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  async removeUser(@Args('id', { type: () => ID }) id: string): Promise<boolean> {
    await this.userService.remove(id);
    return true;
  }
}