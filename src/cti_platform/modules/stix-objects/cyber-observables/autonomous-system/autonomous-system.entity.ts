import { Field, ObjectType } from '@nestjs/graphql';

import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class AutonomousSystem extends CyberObservableCommonProperties {
  @Field(() => Number)
  

  @Field(() => String, { nullable: true })
  
  name?: string;

  @Field(() => String, { nullable: true })
  
  rir?: string;
}