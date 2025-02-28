import { Field, InputType } from '@nestjs/graphql';
import { CommonInput, RelationshipCommonProperties, RelationshipCommonInput} from '../../../../core/types/common-data-types';

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
    Relationship?: [RelationshipCommonProperties];
}

@InputType()
export class UpdateCourseOfActionInput extends CreateCourseOfActionInput {
  
}