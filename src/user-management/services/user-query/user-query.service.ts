

import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/user-management/entities/user.entity';
import { validate as isUUID } from 'uuid';

@Injectable()
export class UserQueryService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  /**
   * Retrieve all users with selected fields and relations
   */
  async findAllUsers(): Promise<User[]> {
    try {
      return await this.userRepository.find({
        relations: ['roles'],
        select: ['id', 'email', 'firstName', 'lastName', 'isEmailVerified', 'createdAt', 'updatedAt'],
      });
    } catch (error) {
      console.error('Error finding all users:', error.stack);
      throw new Error('Failed to retrieve users');
    }
  }

  /**
   * Find a user by ID, ensuring the ID is valid and the user exists
   * @param id - User ID (UUID format)
   */
  async findUserById(id: string): Promise<User> {
    // Validate the ID format
    if (!isUUID(id)) {
      throw new BadRequestException(`Invalid user ID format: ${id}`);
    }

    try {
      const user = await this.userRepository.findOne({
        where: { id },
        relations: ['roles'],
      });

      if (!user) {
        throw new NotFoundException(`User with ID ${id} not found`);
      }

      return user;
    } catch (error) {
      console.error(`Error retrieving user by ID (${id}):`, error.stack);
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new Error('Failed to retrieve user from the database');
    }
  }

  
  async findUserByEmail(email: string): Promise<User> {
    try {
      const user = await this.userRepository.findOne({
        where: { email },
        relations: ['roles'],
        select: {
          id: true,
          email: true,
          password: true,
          firstName: true,
          lastName: true,
          isEmailVerified: true,
          createdAt: true,
          updatedAt: true,
          roles: true
        }
      });

      if (!user) {
        throw new NotFoundException(`User with email ${email} not found`);
      }

      return user;
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }
      console.error('Error finding user by email:', error);
      throw new Error('Failed to retrieve user');
    }
  }
}

