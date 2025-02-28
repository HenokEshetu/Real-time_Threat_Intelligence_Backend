import { Field, ObjectType } from '@nestjs/graphql';
import { Entity, Column } from 'typeorm';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class EmailAddress extends CyberObservableCommonProperties {
  @Field(() => String)
  
  value: string;

  @Field(() => String, { nullable: true })
 
  display_name?: string;

  @Field(() => [String], { nullable: true })
 
  belongs_to_refs?: string[];
}