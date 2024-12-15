import { InputType, Field } from '@nestjs/graphql';
import { IsNotEmpty, IsString, Length } from 'class-validator';

@InputType()
export class ChangePasswordDto {
  @Field()
  @IsNotEmpty()
  oldPassword: string;

  @Field()
  @IsNotEmpty()
  @IsString()
  @Length(8, 20)
  newPassword: string;
}