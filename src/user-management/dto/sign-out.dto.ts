import { InputType, Field } from '@nestjs/graphql';
import { IsString } from 'class-validator';

@InputType()
export class SignOutDto {
  @Field()
  @IsString()
  token: string;
}