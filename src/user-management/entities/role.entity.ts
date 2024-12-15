import { Entity, PrimaryGeneratedColumn, Column, ManyToMany, JoinTable } from 'typeorm';
import { ObjectType, Field, ID } from '@nestjs/graphql';
import { User } from './user.entity';
import { Permission } from './permission.entity';

@ObjectType()
@Entity()
export class Role {
  @Field(() => ID)
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Field()
  @Column({ unique: true })
  name: string;

  @Field()
  @Column()
  description: string;

  @Field(() => [User])
  @ManyToMany(() => User, (user) => user.roles)
  users: User[];

  @Field(() => [Permission])
  @ManyToMany(() => Permission, (permission) => permission.roles)
  @JoinTable()
  permissions: Permission[];
}