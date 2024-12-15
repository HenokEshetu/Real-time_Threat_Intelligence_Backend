import { Entity, PrimaryGeneratedColumn, Column, ManyToMany } from 'typeorm';
import { ObjectType, Field, ID } from '@nestjs/graphql';
import { Role } from './role.entity';

@ObjectType()
@Entity()
export class Permission {
  @Field(() => ID)
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Field()
  @Column({ unique: true })
  name: string;

  @Field()
  @Column()
  description: string;

  @Field(() => [Role])
  @ManyToMany(() => Role, (role) => role.permissions)
  roles: Role[];
}