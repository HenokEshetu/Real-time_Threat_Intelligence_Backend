import { Field, ObjectType } from '@nestjs/graphql';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class MACAddress extends CyberObservableCommonProperties {
  @Field(() => String)
  
  type: string = 'mac_addr';

  @Field(() => String)
  
  value: string;
}