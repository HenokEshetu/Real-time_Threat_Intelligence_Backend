import { Field, ObjectType } from '@nestjs/graphql';
import { Entity, Column } from 'typeorm';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';

@ObjectType()
export class IPv4Address extends CyberObservableCommonProperties {
  @Field(() => String)
  
  value: string;

  @Field(() => String)
  
  type: string = 'ipv4-addr';

  @Field(() => String, { nullable: true })
 
  resolves_to_refs?: string[];

  @Field(() => String, { nullable: true })
 
  belongs_to_refs?: string[];
}