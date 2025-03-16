import { Field, ObjectType } from '@nestjs/graphql';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';
@ObjectType()
export class Mutex extends CyberObservableCommonProperties {
  @Field(() => String)
  type: string = 'mutex';
  @Field(() => String)
  name: string;
}