import { InputType, Field } from '@nestjs/graphql';
import {
  IsOptional,
  Length,
  IsString,
  IsEmail,
  IsBoolean,
} from 'class-validator';

@InputType()
export class UpdateUserDto {
  @Field({ nullable: true })
  @IsOptional()
  @Length(3, 20)
  username?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsString()
  password?: string;

  @IsOptional()
  @IsBoolean()
  deletionRequested?: boolean;
}
