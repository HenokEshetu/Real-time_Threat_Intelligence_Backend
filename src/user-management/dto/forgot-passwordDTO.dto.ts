import { InputType, Field } from '@nestjs/graphql';
import { IsEmail } from 'class-validator';


@InputType()
export class forgotPasswordDto {
  @Field()
  @IsEmail()
  email: string;
}