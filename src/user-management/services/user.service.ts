import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/user-management/entities/user.entity';
import { CreateUserDto } from 'src/user-management/dto/create-user.dto';
import { UpdateUserDto } from 'src/user-management/dto/update-user.dto';
import { hashPassword } from 'src/user-management/utils/password.util';
import { UserQueryService } from 'src/user-management/services/user-query.service';
import { UserCommandService } from 'src/user-management/services/user-command.service';
import { EmailVerificationService } from './email-verification.service';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private userQueryService: UserQueryService,
    private userCommandService: UserCommandService,
    private emailVerificationService: EmailVerificationService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await hashPassword(createUserDto.password);
    const userWithHashedPassword = {
      ...createUserDto,
      password: hashedPassword,
    };
    const userCreated = await this.userCommandService.createUser(
      userWithHashedPassword,
    );
    const token =
      await this.emailVerificationService.createVerificationToken(userCreated);
    await this.emailVerificationService.sendVerificationEmail(
      userCreated,
      token,
    );
    return userCreated;
  }

  async findAll(): Promise<User[]> {
    return this.userQueryService.findAllUsers();
  }

  async findOne(id: string): Promise<User> {
    return this.userQueryService.findUserById(id);
  }

  async findBy(where: any): Promise<User> {
    return this.userQueryService.findUserBy(where);
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

  async requestDeletion(id: string): Promise<void> {
    await this.userCommandService.updateUser(id, { deletionRequested: true });
  }

  async approveDeletion(id: string): Promise<void> {
    const user = await this.userQueryService.findUserById(id);
    if (!user || !user.deletionRequested) {
      throw new NotFoundException('No pending deletion for that user');
    }
    await this.userCommandService.removeUser(id);
  }
}
