import { Field, InputType } from '@nestjs/graphql';
import { IsNotEmpty, IsString, IsUrl } from 'class-validator';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateUrlInput extends CyberObservableCommonInput{
  @Field(() => String)
  @IsNotEmpty()
  @IsString()
  @IsUrl({}, { message: 'Invalid URL format' })
  value: string;
}

@InputType()
export class UpdateUrlInput extends CyberObservableCommonInput {
  @Field(() => String)
  @IsNotEmpty()
  @IsString()
  @IsUrl({}, { message: 'Invalid URL format' })
  value: string;
}