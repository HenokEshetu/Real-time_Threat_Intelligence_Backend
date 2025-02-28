import { Field, InputType } from '@nestjs/graphql';
import { RelationshipCommonProperties, CommonInput, RelationshipCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateNoteInput extends CommonInput {
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

  @Field(() => [RelationshipCommonInput], { nullable: true })
  Relationship?: [RelationshipCommonProperties];

}

@InputType()
export class UpdateNoteInput extends CreateNoteInput {
  
}