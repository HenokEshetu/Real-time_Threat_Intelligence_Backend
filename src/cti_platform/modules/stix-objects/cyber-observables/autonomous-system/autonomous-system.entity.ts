import { Field, ObjectType } from '@nestjs/graphql';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';
import { IntegerType } from 'typeorm';
@ObjectType()
export class AutonomousSystem extends CyberObservableCommonProperties {
  @Field(() => Number)
  number: IntegerType;
  @Field(() => String, { nullable: true })
  name?: string;
  @Field(() => String, { nullable: true }) 
  rir?: string;
}