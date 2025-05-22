import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { FindOptionsWhere, Repository } from 'typeorm';
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
        relations: ['role', 'role.permissions'],
        select: [
          'userId',
          'email',
          'firstName',
          'lastName',
          'isEmailVerified',
          'createdAt',
          'updatedAt',
        ],
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
        where: { userId: id },
        relations: ['role', 'role.permissions'],
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

  async findUserBy(where: FindOptionsWhere<User> | FindOptionsWhere<User>[]) {
    try {
      const user = await this.userRepository.findOne({
        where: where,
        relations: ['role', 'role.permissions'],
      });

      if (!user) {
        throw new NotFoundException(`User with filter ${where} not found`);
      }

      return user;
    } catch (error) {
      console.error(`Error retrieving user by filter (${where}):`, error.stack);
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
        relations: ['role', 'role.permissions'],
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
