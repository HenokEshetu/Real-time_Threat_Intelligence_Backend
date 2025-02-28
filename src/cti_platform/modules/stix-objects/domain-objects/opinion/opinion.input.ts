import { Field, InputType } from '@nestjs/graphql';
import { CommonInput, RelationshipCommonProperties, RelationshipCommonInput } from '../../../../core/types/common-data-types';
@InputType()
export class CreateOpinionInput extends CommonInput {
  @Field(() => String)
  explanation: string;

  @Field(() => [String])
  object_refs: string[];

  @Field(() => String)
  opinion: 'strongly-disagree' | 'disagree' | 'neutral' | 'agree' | 'strongly-agree';

  @Field(() => [String], { nullable: true })
  authors?: string[];

@Field(() => [RelationshipCommonInput], { nullable: true })
  Relationship?: [RelationshipCommonProperties];


}

@InputType()
export class UpdateOpinionInput extends CreateOpinionInput {
  
}