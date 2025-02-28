import { Field, ObjectType } from '@nestjs/graphql';

import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class Campaign extends CommonProperties {
  @Field(() => String)
  type: string = 'campaign';

  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  
  description?: string;

  @Field(() => [String], { nullable: true })

  aliases?: string[];

  @Field(() => Date, { nullable: true })

  first_seen?: Date;

  @Field(() => Date, { nullable: true })
  
  last_seen?: Date;

  @Field(() => String, { nullable: true })

  objective?: string;
  
  @Field(() => [RelationshipCommonProperties], { nullable: true })
        relationship?: RelationshipCommonProperties[];
}