// attack-pattern.input.ts
import { Field, InputType } from '@nestjs/graphql';
import { KillChainPhase, RelationshipCommonInput, KillChainPhaseInput, CommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateAttackPatternInput extends CommonInput {
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [String], { nullable: true })
  aliases?: string[];

  @Field(() => [KillChainPhaseInput], { nullable: true })
  kill_chain_phases?: KillChainPhase[];

  @Field(() => String, { nullable: true })
  version?: string;

  @Field(() => [RelationshipCommonInput], { nullable: true })
  relationship?: RelationshipCommonInput[];

  // MITRE Extension Fields
  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_contributors?: string[];

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => String, { nullable: true })
  x_mitre_detection?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_domains?: string[];

  @Field(() => Boolean, { nullable: true })
  x_mitre_is_subtechnique?: boolean;

  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_platforms?: string[];

  @Field(() => String, { nullable: true })
  x_mitre_version?: string;
}

@InputType()
export class UpdateAttackPatternInput extends CreateAttackPatternInput {
  // Inherits all fields from CreateAttackPatternInput
}