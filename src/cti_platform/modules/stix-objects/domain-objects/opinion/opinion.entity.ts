import { Field, ObjectType, Int } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class Opinion extends CommonProperties {
  @Field(() => String)
  type: string = 'opinion';

  @Field(() => String)
  explanation: string;

  @Field(() => [String])
  object_refs: string[];

  @Field(() => String)
  opinion: 'strongly-disagree' | 'disagree' | 'neutral' | 'agree' | 'strongly-agree';

  @Field(() => [String], { nullable: true })
  authors?: string[];

  @Field(() => [RelationshipCommonProperties], { nullable: true })
  relationship?: RelationshipCommonProperties[];

}