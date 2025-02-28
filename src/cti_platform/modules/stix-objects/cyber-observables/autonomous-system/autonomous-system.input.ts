import { Field, InputType, Int } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';
@InputType()
export class CreateAutonomousSystemInput extends CyberObservableCommonInput {
  @Field(() => Int)
  number: number;

  @Field(() => String, { nullable: true })
  name?: string;

  @Field(() => String, { nullable: true })
  rir?: string;
}

@InputType()
export class UpdateAutonomousSystemInput extends CyberObservableCommonInput {
  @Field(() => Int, { nullable: true })
  number?: number;

  @Field(() => String, { nullable: true })
  name?: string;

  @Field(() => String, { nullable: true })
  rir?: string;
}