import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateSoftwareInput extends  CyberObservableCommonInput {
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  cpe?: string;

  @Field(() => [String], { nullable: true })
  swid?: string[];

  @Field(() => [String], { nullable: true })
  languages?: string[];

  @Field(() => String, { nullable: true })
  vendor?: string;

  @Field(() => String, { nullable: true })
  version?: string;
}

@InputType()
export class UpdateSoftwareInput extends  CyberObservableCommonInput{
  @Field(() => String, { nullable: true })
  name?: string;

  @Field(() => String, { nullable: true })
  cpe?: string;

  @Field(() => [String], { nullable: true })
  swid?: string[];

  @Field(() => [String], { nullable: true })
  languages?: string[];

  @Field(() => String, { nullable: true })
  vendor?: string;

  @Field(() => String, { nullable: true })
  version?: string;
}