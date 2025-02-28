import { ObjectType, Field, ID } from '@nestjs/graphql';
import GraphQLJSON from 'graphql-type-json'; // Import GraphQL JSON Scalar

@ObjectType()
export class Bundle {
  @Field(() => String)
  type: string = 'bundle';

  @Field(() => ID)
  id: string;

  @Field(() => [GraphQLJSON]) //  Use GraphQLJSON to store arbitrary JSON objects
  objects: any[];
}
