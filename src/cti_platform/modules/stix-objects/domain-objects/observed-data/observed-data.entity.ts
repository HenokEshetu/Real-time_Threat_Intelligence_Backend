import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';

@ObjectType()
export class ObservedData extends CommonProperties {
  @Field(() => String)
  type: string = 'observed-data';

  @Field(() => [String])
  object_refs: string[];

  @Field(() => Date)
  first_observed: Date;

  @Field(() => Date)
  last_observed: Date;

  @Field(() => Number)
  number_observed: number;

  @Field(() => [RelationshipCommonProperties], { nullable: true })
      relationship?: RelationshipCommonProperties[];
}