import { Field, ObjectType, Int } from '@nestjs/graphql';

import { CommonProperties } from '../../../core/types/common-data-types';


@ObjectType()
export class Sighting extends CommonProperties {
  @Field(() => String)
 
  type: string = 'sighting';

  @Field(() => String)
  
  sighting_of_ref: string;

  @Field(() => [String], { nullable: true })
 
  observed_data_refs?: string[];

  @Field(() => [String], { nullable: true })
 
  where_sighted_refs?: string[];

  @Field(() => String, { nullable: true })
 
  summary?: string;

  @Field(() => Date)
 
  first_seen: Date;

  @Field(() => Date)

  last_seen: Date;

  @Field(() => Int, { nullable: true })
 
  count?: number;

  @Field(() => Boolean, { nullable: true })
 
  detected?: boolean;
}