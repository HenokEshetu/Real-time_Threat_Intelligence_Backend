import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';
@InputType()
export class CreateIPv4AddressInput extends CyberObservableCommonInput {
  @Field(() => String)
  value: string;

  @Field(() => [String], { nullable: true })
  resolves_to_refs?: string[];

  @Field(() => [String], { nullable: true })
  belongs_to_refs?: string[];
}

@InputType()
export class UpdateIPv4AddressInput extends CreateIPv4AddressInput {}