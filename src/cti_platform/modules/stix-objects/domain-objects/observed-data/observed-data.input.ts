import { Field, InputType } from '@nestjs/graphql';
import { RelationshipCommonProperties, CommonInput, RelationshipCommonInput } from '../../../../core/types/common-data-types';


@InputType()
export class CreateObservedDataInput extends CommonInput {
  @Field(() => [String])
  object_refs: string[];

  @Field(() => Date)
  first_observed: Date;

  @Field(() => Date)
  last_observed: Date;

  @Field(() => Number)
  number_observed: number;

  @Field(() => [RelationshipCommonInput], { nullable: true })
  Relationship?: [RelationshipCommonProperties];


}

@InputType()
export class UpdateObservedDataInput extends CreateObservedDataInput {
  
}