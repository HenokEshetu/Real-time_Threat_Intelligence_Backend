import { Field, ObjectType } from '@nestjs/graphql';

import { CommonProperties,RelationshipCommonProperties, } from '../../../../core/types/common-data-types';


@ObjectType()
export class Incident extends CommonProperties {
  @Field(() => String)
 
  type: string = 'incident';

  @Field(() => String)
 
  name: string;

  @Field(() => String, { nullable: true })

  description?: string;

  @Field(() => [String], { nullable: true })
  
  aliases?: string[];

  @Field(() => Date, { nullable: true })

  first_seen?: Date;

  @Field(() => Date, { nullable: true })
  
  last_seen?: Date;

  @Field(() => [String], { nullable: true })
 
  incident_types?: string[];

  @Field(() => String, { nullable: true })
 
  severity?: string;

  @Field(() => String, { nullable: true })
 
  status?: string;

  @Field(() => String, { nullable: true })
 
  source?: string;

  @Field(() => [String], { nullable: true })
 
  affected_assets?: string[];

  @Field(() => [RelationshipCommonProperties], { nullable: true })
      relationship?: RelationshipCommonProperties[];
}