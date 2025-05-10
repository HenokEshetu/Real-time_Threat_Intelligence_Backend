// course-of-action.input.ts
import { Field, InputType } from '@nestjs/graphql';
import { CommonInput, RelationshipCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateCourseOfActionInput extends CommonInput {
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => String, { nullable: true })
  action?: string;

  @Field(() => String, { nullable: true })
  action_type?: string;

  @Field(() => String, { nullable: true })
  action_bin?: string;

  @Field(() => String, { nullable: true })
  action_reference?: string;

  @Field(() => [RelationshipCommonInput], { nullable: true })
  relationship?: RelationshipCommonInput[];

  // MITRE Extension Fields
  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => [String], { nullable: true })
  x_mitre_domains?: string[];

  @Field(() => String, { nullable: true })
  x_mitre_version?: string;

  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;
}

@InputType()
export class UpdateCourseOfActionInput extends CreateCourseOfActionInput {
  // Inherits all fields from CreateCourseOfActionInput
}