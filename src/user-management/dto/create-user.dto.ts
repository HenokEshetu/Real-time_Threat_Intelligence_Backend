import { InputType, Field } from '@nestjs/graphql';
import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

@InputType()
export class CreateUserDto {
  @Field()
  @IsNotEmpty()
  @Length(3, 20)
  username: string;

  @Field()
  @IsEmail()
  email: string;
  @Field()
  @IsString()
  firstName: string;

  @Field()
  @IsString()
  lastName: string;

  @Field()
  @IsNotEmpty()
  @Length(8, 20)
  password: string;
}