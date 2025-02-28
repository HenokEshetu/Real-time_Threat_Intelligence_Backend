import { Field, InputType } from '@nestjs/graphql';
import { IsOptional, IsString, IsArray, ValidateNested, IsISO8601 } from 'class-validator';
import { Type } from 'class-transformer';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
class WindowsRegistryValueInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  name?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  data?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  data_type?: string;
}

@InputType()
export class CreateWindowsRegistryKeyInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  key?: string;

  @Field(() => [WindowsRegistryValueInput], { nullable: true })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => WindowsRegistryValueInput)
  values?: WindowsRegistryValueInput[];

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  modified_time?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  creator_user_ref?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  number_of_subkeys?: string;
}

@InputType()
export class UpdateWindowsRegistryKeyInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  key?: string;

  @Field(() => [WindowsRegistryValueInput], { nullable: true })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => WindowsRegistryValueInput)
  values?: WindowsRegistryValueInput[];

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  modified_time?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  creator_user_ref?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  number_of_subkeys?: string;
}