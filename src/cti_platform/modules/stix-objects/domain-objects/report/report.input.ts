import { Field, InputType } from '@nestjs/graphql';

import { RelationshipCommonInput, RelationshipCommonProperties, CommonInput } from '../../../../core/types/common-data-types';



@InputType()
export class CreateReportInput extends CommonInput {
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [String])
  report_types: string[];

  @Field(() => Date)
  published: Date;

  @Field(() => [String])
  object_refs: string[];

  @Field(() => [String], { nullable: true })
  authors?: string[];

@Field(() => [RelationshipCommonInput], { nullable: true })
  Relationship?: [RelationshipCommonProperties];


}

@InputType()
export class UpdateReportInput extends CreateReportInput {
 
}