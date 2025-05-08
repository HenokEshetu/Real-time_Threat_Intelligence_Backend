import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';

@ObjectType()
export class Report extends CommonProperties {
  @Field(() => String)
  type: string = 'report';

  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  // Allow the array to be nullable and the elements to be nullable
  @Field(() => [String], { nullable: 'itemsAndList' })
  report_types?: string[];

  @Field(() => Date)
  published: Date;

  @Field(() => [String])
  object_refs: string[];

  @Field(() => [String], { nullable: true })
  authors?: string[];

  @Field(() => [RelationshipCommonProperties], { nullable: true })
  relationship?: RelationshipCommonProperties[];
}