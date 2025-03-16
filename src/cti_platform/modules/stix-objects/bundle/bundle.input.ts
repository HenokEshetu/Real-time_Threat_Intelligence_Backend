import { InputType, Field, ID } from '@nestjs/graphql';
import GraphQLJSON from 'graphql-type-json'; // Import GraphQL JSON Scalar

@InputType()
export class CreateBundleInput {
  @Field(() => String, { defaultValue: 'bundle' })
  type: string = 'bundle';

  @Field(() => ID)
  id: string; // Unique identifier for the Bundle

  @Field(() => [GraphQLJSON]) // ✅ Use GraphQLJSON for input objects
  objects: any[];
}

@InputType()
export class UpdateBundleInput extends CreateBundleInput {}
