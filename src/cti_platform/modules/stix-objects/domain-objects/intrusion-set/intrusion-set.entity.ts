import { Field, ObjectType } from '@nestjs/graphql';

import { CommonProperties,RelationshipCommonProperties, KillChainPhase } from '../../../../core/types/common-data-types';


@ObjectType()
export class IntrusionSet extends CommonProperties {

  @Field(() => String)
  type: string = 'intrusion-set';

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

  @Field(() => [String], { nullable: true })
  goals?: string[];

  @Field(() => String, { nullable: true })
  resource_level?: string;

  @Field(() => String, { nullable: true })
  primary_motivation?: string;

  @Field(() => [String], { nullable: true })
  secondary_motivations?: string[];

  @Field(() => [KillChainPhase], { nullable: true })
  kill_chain_phases?: KillChainPhase[];

  @Field(() => [RelationshipCommonProperties], { nullable: true })
  relationship?: RelationshipCommonProperties[];

}