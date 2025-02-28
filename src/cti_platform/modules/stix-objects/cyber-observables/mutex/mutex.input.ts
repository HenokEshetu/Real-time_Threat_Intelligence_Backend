import { Field, InputType } from '@nestjs/graphql';
import { IsString, IsNotEmpty, MaxLength } from 'class-validator';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateMutexInput extends CyberObservableCommonInput {
  @Field(() => String)
  @IsString()
  @IsNotEmpty()
  @MaxLength(512, { message: 'Mutex name cannot exceed 512 characters' })
  name: string;
}

@InputType()
export class UpdateMutexInput extends CyberObservableCommonInput {
  @Field(() => String)
  @IsString()
  @IsNotEmpty()
  @MaxLength(512, { message: 'Mutex name cannot exceed 512 characters' })
  name: string;
}