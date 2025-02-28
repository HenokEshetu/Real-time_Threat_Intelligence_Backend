import { Field, InputType } from '@nestjs/graphql';
import { ThreatActorType, RelationshipCommonInput, RelationshipCommonProperties, CommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateThreatActorInput extends CommonInput {
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

  @Field(() => [RelationshipCommonInput], { nullable: true })
  Relationship?: [RelationshipCommonProperties];

}

@InputType()
export class UpdateThreatActorInput extends CreateThreatActorInput {
  
}