import { Field, InputType } from '@nestjs/graphql';
import { CommonInput, RelationshipCommonProperties, RelationshipCommonInput} from '../../../../core/types/common-data-types';

@InputType()
export class CreateGroupingInput extends CommonInput{
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => String)
  context: string;

  @Field(() => [String])
  object_refs: string[];


    @Field(() => [RelationshipCommonInput], { nullable: true })
      Relationship?: [RelationshipCommonProperties];
  }

@InputType()
export class UpdateGroupingInput extends CreateGroupingInput {
  
}