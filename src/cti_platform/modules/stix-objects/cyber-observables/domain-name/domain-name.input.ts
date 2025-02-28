import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateDomainNameInput extends CyberObservableCommonInput {
  @Field(() => String)
  value: string;

  @Field(() => [String], { nullable: true })
  resolves_to_refs?: string[];
}

@InputType()
export class UpdateDomainNameInput extends CyberObservableCommonInput{
  @Field(() => String, { nullable: true })
  value?: string;

  @Field(() => [String], { nullable: true })
  resolves_to_refs?: string[];
}