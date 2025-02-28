import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class Note extends CommonProperties {
  @Field(() => String)
  type: string = 'note';

  @Field(() => String)
  abstract: string;

  @Field(() => String)
  content: string;

  @Field(() => [String])
  object_refs: string[];

  @Field(() => [String], { nullable: true })
  authors?: string[];

  @Field(() => String, { nullable: true })
  content_type?: string;

@Field(() => [RelationshipCommonProperties], { nullable: true })
    relationship?: RelationshipCommonProperties[];

}