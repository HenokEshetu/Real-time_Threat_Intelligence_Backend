import { Field, ObjectType } from '@nestjs/graphql';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class Url extends CyberObservableCommonProperties {
  @Field(() => String)
  
  type: string = 'url';

  @Field(() => String)
 
  value: string;
}