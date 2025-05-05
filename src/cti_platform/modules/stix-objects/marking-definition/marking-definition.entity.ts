import { Field, ObjectType, Int } from '@nestjs/graphql';
import { CommonProperties } from 'src/cti_platform/core/types/common-data-types';
import { GraphQLJSONObject } from 'graphql-scalars';

@ObjectType()
export class MarkingDefinition extends CommonProperties {
  @Field(() => String)
  type: string = 'marking-definition';

  @Field(() => String, { nullable: true })
  name?: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => String)
  definition_type: string;

  @Field(() => GraphQLJSONObject, { nullable: true })
  definition?: Record<string, any>;


  @Field(() => String, { nullable: true })
  created_by_ref?: string;

  @Field(() => [String], { nullable: true })
  object_marking_refs?: string[];

  @Field(() => [String], { nullable: true })
  granular_markings?: string[];
}

@ObjectType()
export class MarkingDefinitionSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [MarkingDefinition])
  results: MarkingDefinition[];
}