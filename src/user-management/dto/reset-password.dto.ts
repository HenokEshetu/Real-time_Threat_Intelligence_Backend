import { InputType, Field } from '@nestjs/graphql';
import { IsEmail } from 'class-validator';
import { IsString, MinLength } from 'class-validator';


@InputType()
export class ResetPasswordDto {
  @Field()
  @IsEmail()
  email: string;

  @Field()
  @IsString()
  token: string;

  @Field()
  @IsString()
  @MinLength(8)
  newPassword: string;
}