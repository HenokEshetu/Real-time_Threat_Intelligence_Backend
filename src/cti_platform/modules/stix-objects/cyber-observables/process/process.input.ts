import { Field, InputType } from '@nestjs/graphql';
import { GraphQLJSONObject } from 'graphql-scalars';
import { Dictionary } from '../../../../core/types/common-data-types';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateProcessInput extends CyberObservableCommonInput{
  @Field(() => Boolean, { nullable: true })
  is_hidden?: boolean;

  @Field(() => Number, { nullable: true })
  pid?: number;

  @Field(() => String, { nullable: true })
  created_time?: string;

  @Field(() => String, { nullable: true })
  cwd?: string;

  @Field(() => String, { nullable: true })
  command_line?: string;

  @Field(() => [String], { nullable: true })
  environment_variables?: string[];

  @Field(() => [String], { nullable: true })
  opened_connection_refs?: string[];

  @Field(() => String, { nullable: true })
  creator_user_ref?: string;

  @Field(() => String, { nullable: true })
  image_ref?: string;

  @Field(() => String, { nullable: true })
  parent_ref?: string;

  @Field(() => [String], { nullable: true })
  child_refs?: string[];

  @Field(() => GraphQLJSONObject, { nullable: true })
  arguments?: Dictionary;

  @Field(() => GraphQLJSONObject, { nullable: true })
  service_dll_refs?: Dictionary;
}

@InputType()
export class UpdateProcessInput extends CreateProcessInput {
  
}