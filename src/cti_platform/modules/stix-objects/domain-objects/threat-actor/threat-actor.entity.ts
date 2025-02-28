import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties, ThreatActorType, } from '../../../../core/types/common-data-types';


@ObjectType()
export class ThreatActor extends CommonProperties {
  @Field(() => String)
  type: string = 'threat-actor';

  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [ThreatActorType])
  threat_actor_types: ThreatActorType[];

  @Field(() => [String], { nullable: true })
  aliases?: string[];

  @Field(() => Date, { nullable: true })
  first_seen?: Date;

  @Field(() => Date, { nullable: true })
  last_seen?: Date;

  @Field(() => [String], { nullable: true })
  roles?: string[];

  @Field(() => [String], { nullable: true })
  goals?: string[];

  @Field(() => String, { nullable: true })
  sophistication?: string;

  @Field(() => String, { nullable: true })
  resource_level?: string;

  @Field(() => Boolean, { nullable: true })
  primary_motivation?: boolean;

  @Field(() => [String], { nullable: true })
  secondary_motivations?: string[];

  @Field(() => String, { nullable: true })
  personal_motivations?: string;

  @Field(() => [RelationshipCommonProperties], { nullable: true })
      relationship?: RelationshipCommonProperties[];
}