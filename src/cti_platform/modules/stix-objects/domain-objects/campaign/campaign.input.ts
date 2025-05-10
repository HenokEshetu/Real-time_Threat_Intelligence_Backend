// campaign.input.ts
import { Field, InputType } from '@nestjs/graphql';
import { CommonInput, RelationshipCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateCampaignInput extends CommonInput {
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

  @Field(() => [RelationshipCommonInput], { nullable: true })
  relationship?: RelationshipCommonInput[];

  // MITRE Extension Fields
  @Field(() => String, { nullable: true })
  x_mitre_first_seen_citation?: string;

  @Field(() => String, { nullable: true })
  x_mitre_last_seen_citation?: string;

  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => String, { nullable: true })
  x_mitre_version?: string;

  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_contributors?: string[];

  @Field(() => [String], { nullable: true })
  x_mitre_domains?: string[];
}

@InputType()
export class UpdateCampaignInput extends CreateCampaignInput {
  // Inherits all fields from CreateCampaignInput
}