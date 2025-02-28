import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateEmailAddressInput extends CyberObservableCommonInput {
  @Field(() => String)
  value: string;

  @Field(() => String, { nullable: true })
  display_name?: string;

  @Field(() => [String], { nullable: true })
  belongs_to_refs?: string[];
}

@InputType()
export class UpdateEmailAddressInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  value?: string;

  @Field(() => String, { nullable: true })
  display_name?: string;

  @Field(() => [String], { nullable: true })
  belongs_to_refs?: string[];
}