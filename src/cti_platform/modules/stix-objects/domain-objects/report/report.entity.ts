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

  @Field(() => [String])
  report_types: string[];

  @Field(() => Date)
  published: Date;

  @Field(() => [String])
  object_refs: string[];

  @Field(() => [String], { nullable: true })
  authors?: string[];

@Field(() => [RelationshipCommonProperties], { nullable: true })
      relationship?: RelationshipCommonProperties[];
}

