// attack-pattern.entity.ts
import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, KillChainPhase, RelationshipCommonProperties } from '../../../../core/types/common-data-types';

@ObjectType()
export class AttackPattern extends CommonProperties {
  @Field(() => String)
  type: string = 'attack-pattern';

  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [String], { nullable: true })
  aliases?: string[];

  @Field(() => [KillChainPhase], { nullable: true })
  kill_chain_phases?: KillChainPhase[];

  @Field(() => String, { nullable: true })
  version?: string;

  @Field(() => [RelationshipCommonProperties], { nullable: true })
  relationship?: RelationshipCommonProperties[];

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