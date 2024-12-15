import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/user-management/entities/user.entity';
import { CreateUserDto } from 'src/user-management/dto/create-user.dto';
import { UpdateUserDto } from 'src/user-management/dto/update-user.dto';
import { hashPassword } from 'src/user-management/utils/password.util';
import * as bcrypt from 'bcrypt';


import { UserQueryService } from 'src/user-management/services/user-query/user-query.service';
import { UserCommandService } from 'src/user-management/services/user-command/user-command.service';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private userQueryService: UserQueryService,
    private userCommandService: UserCommandService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    // Hash password before creating the user
    const hashedPassword = await hashPassword(createUserDto.password);
    const userWithHashedPassword = { ...createUserDto, password: hashedPassword };
    return this.userCommandService.createUser(userWithHashedPassword);
  }

  async findAll(): Promise<User[]> {
    return this.userQueryService.findAllUsers();
  }

  async findOne(id: string): Promise<User> {
    return this.userQueryService.findUserById(id);
  }

  async findByEmail(email: string): Promise<User> {
    return this.userQueryService.findUserByEmail(email);
  }

  async update(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    return this.userCommandService.updateUser(id, updateUserDto);
  }

  async remove(id: string): Promise<void> {
    return this.userCommandService.removeUser(id);
  }
}