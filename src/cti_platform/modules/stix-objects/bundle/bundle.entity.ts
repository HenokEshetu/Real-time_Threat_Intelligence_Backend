import { ObjectType, Field, ID } from '@nestjs/graphql';
import { GraphQLJSONObject } from 'graphql-scalars';
import { CommonProperties } from 'src/cti_platform/core/types/common-data-types';
@ObjectType()
export class Bundle extends CommonProperties{
  @Field(() => String)
  type: string = 'bundle';

  @Field(() => ID)
  id: string;

  @Field(() => [GraphQLJSONObject]) //  Use GraphQLJSON to store arbitrary JSON objects
  objects: any[];
}
