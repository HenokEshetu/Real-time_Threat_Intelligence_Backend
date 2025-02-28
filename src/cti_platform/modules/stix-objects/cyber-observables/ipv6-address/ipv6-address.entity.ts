import { Field, ObjectType } from '@nestjs/graphql';
import { Entity, Column } from 'typeorm';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class IPv6Address extends CyberObservableCommonProperties {
  @Field(() => String)
  
  type: string = 'ipv6-addr';

  @Field(() => String)
 
  value: string;

  @Field(() => String, { nullable: true })
 
  resolves_to_refs?: string;
}