// course-of-action.entity.ts
import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';

@ObjectType()
export class CourseOfAction extends CommonProperties {
  @Field(() => String)
  type: string = 'course-of-action';

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

  @Field(() => [RelationshipCommonProperties], { nullable: true })
  relationship?: RelationshipCommonProperties[];

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