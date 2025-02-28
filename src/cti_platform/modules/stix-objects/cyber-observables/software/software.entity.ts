import { Field, ObjectType } from '@nestjs/graphql';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';
import { CyberObservableCommonProperties, Dictionary } from '../../../../core/types/common-data-types';


@ObjectType()
export class Software extends CyberObservableCommonProperties {
  @Field(() => String)
 
  name: string;

  @Field(() => String, { nullable: true })
 
  cpe?: string;

  @Field(() => [String], { nullable: true })
 
  swid?: string[];

  @Field(() => [String], { nullable: true })
 
  languages?: string[];

  @Field(() => String, { nullable: true })
  
  vendor?: string;

  @Field(() => String, { nullable: true })
 
  version?: string;
}