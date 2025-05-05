import { InputType, Field, ID } from '@nestjs/graphql';
import { GraphQLJSONObject } from 'graphql-scalars';
 
import { CommonInput} from 'src/cti_platform/core/types/common-data-types';
@InputType()
export class CreateBundleInput extends CommonInput{
  @Field(() => String, { defaultValue: 'bundle' })
  type: string = 'bundle';

  @Field(() => ID)
  id: string; // Unique identifier for the Bundle

  @Field(() => [GraphQLJSONObject]) //Use GraphQLJSON for input objects
  objects: any[];
}

@InputType()
export class UpdateBundleInput extends CreateBundleInput {}
