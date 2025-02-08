import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/user-management/entities/user.entity';
import { CreateUserDto } from 'src/user-management/dto/create-user.dto';
import { UpdateUserDto } from 'src/user-management/dto/update-user.dto';
import { hashPassword } from 'src/user-management/utils/password.util';
import { UserQueryService } from 'src/user-management/services/user-query/user-query.service';

@Injectable()
export class UserCommandService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private userQueryService: UserQueryService,
  ) {}

  async createUser(createUserDto: CreateUserDto): Promise<User> {
    try {
      const existingUser = await this.userQueryService.findUserByEmail(createUserDto.email).catch(() => null);

      if (existingUser) {
        throw new ConflictException('Email already exists');
      }

      const hashedPassword = createUserDto.password;
      const user = this.userRepository.create({
        ...createUserDto,
        password: hashedPassword,
      });

      return await this.userRepository.save(user);
    } catch (error) {
      if (error instanceof ConflictException) {
        throw error;
      }
      console.error('Error creating user:', error);
      throw new Error('Failed to create user');
    }
  }

  async updateUser(id: string, updateUserDto: UpdateUserDto): Promise<User> {
    try {
      const user = await this.userQueryService.findUserById(id);
      
      if (updateUserDto.password) {
        updateUserDto.password = await hashPassword(updateUserDto.password);
      }

      Object.assign(user, updateUserDto);
      return await this.userRepository.save(user);
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      console.error('Error updating user:', error);
      throw new Error('Failed to update user');
    }
  }

  async removeUser(id: string): Promise<void> {
    try {
      const user = await this.userQueryService.findUserById(id);
      await this.userRepository.remove(user);
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      console.error('Error removing user:', error);
      throw new Error('Failed to remove user');
    }
  }
}