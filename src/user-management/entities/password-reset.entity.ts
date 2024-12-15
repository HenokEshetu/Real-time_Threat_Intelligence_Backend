import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, ManyToOne } from 'typeorm';
import { ObjectType, Field, ID } from '@nestjs/graphql';
import { User } from './user.entity';

@ObjectType()
@Entity()
export class PasswordReset {
  @Field(() => ID)
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Field()
  @Column()
  token: string;

  @Field()
  @Column()
  userId: string;

  @Field()
  @Column({ default: false })
  used: boolean;

  @Field()
  @CreateDateColumn()
  createdAt: Date;

  @Field()
  @Column()
  expiresAt: Date;

  @ManyToOne(() => User)
  user: User;
}