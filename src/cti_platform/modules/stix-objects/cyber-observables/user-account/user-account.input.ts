import { Field, InputType } from '@nestjs/graphql';
import { IsBoolean, IsOptional, IsString, IsISO8601 } from 'class-validator';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateUserAccountInput extends CyberObservableCommonInput  {
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  user_id?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  credential?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  account_login?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  account_type?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  display_name?: string;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  is_service_account?: boolean;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  is_privileged?: boolean;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  can_escalate_privs?: boolean;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  is_disabled?: boolean;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_created?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_expires?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  credential_last_changed?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_first_login?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_last_login?: string;
}

@InputType()
export class UpdateUserAccountInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  user_id?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  credential?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  account_login?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  account_type?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsString()
  display_name?: string;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  is_service_account?: boolean;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  is_privileged?: boolean;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  can_escalate_privs?: boolean;

  @Field(() => Boolean, { nullable: true })
  @IsOptional()
  @IsBoolean()
  is_disabled?: boolean;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_created?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_expires?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  credential_last_changed?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_first_login?: string;

  @Field(() => String, { nullable: true })
  @IsOptional()
  @IsISO8601()
  account_last_login?: string;
}