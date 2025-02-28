import { Field, InputType } from '@nestjs/graphql';
import {  CommonInput, RelationshipCommonInput,RelationshipCommonProperties,  } from '../../../../core/types/common-data-types';


@InputType()
export class CreateIncidentInput extends CommonInput {
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

  @Field(() => [RelationshipCommonInput], { nullable: true })
  Relationship?: [RelationshipCommonProperties];

}




@InputType()
export class UpdateIncidentInput extends CreateIncidentInput{
  
}