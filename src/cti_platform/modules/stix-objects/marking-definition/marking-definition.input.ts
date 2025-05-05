import { Field, InputType } from '@nestjs/graphql';
import { CommonInput } from 'src/cti_platform/core/types/common-data-types';
import { PartialType } from '@nestjs/graphql';
import { GraphQLJSONObject } from 'graphql-scalars';

@InputType()
export class CreateMarkingDefinitionInput extends CommonInput {
  @Field(() => String)
  definition_type: string;

  @Field(() => GraphQLJSONObject, { nullable: true })
  definition?: Record<string, any>;

  @Field(() => String, { nullable: true })
  name?: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => String, { nullable: true })
  created_by_ref?: string;

  @Field(() => [String], { nullable: true })
  object_marking_refs?: string[];

  @Field(() => [String], { nullable: true })
  granular_markings?: string[];
}

@InputType()
export class UpdateMarkingDefinitionInput extends CreateMarkingDefinitionInput {}

@InputType()
export class SearchMarkingDefinitionInput extends PartialType(CreateMarkingDefinitionInput) {}