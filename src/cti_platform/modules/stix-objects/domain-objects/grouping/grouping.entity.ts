import { Field, ObjectType } from '@nestjs/graphql';

import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class Grouping extends CommonProperties {
  @Field(() => String)
  
  type: string = 'grouping';

  @Field(() => String)
 
  name: string;

  @Field(() => String, { nullable: true })
  
  description?: string;

  @Field(() => String)
  
  context: string;

  @Field(() => [String])
  
  object_refs: string[];

  @Field(() => [RelationshipCommonProperties], { nullable: true })
      relationship?: RelationshipCommonProperties[];
}