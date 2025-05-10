// tool.input.ts
import { Field, InputType } from '@nestjs/graphql';
import { ToolType, KillChainPhaseInput, CommonInput, RelationshipCommonInput, KillChainPhase } from '../../../../core/types/common-data-types';

@InputType()
export class CreateToolInput extends CommonInput {
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [ToolType])
  tool_types: ToolType[];

  @Field(() => [String], { nullable: true })
  aliases?: string[];

  @Field(() => [KillChainPhaseInput], { nullable: true })
  kill_chain_phases?: KillChainPhase[];

  @Field(() => String, { nullable: true })
  tool_version?: string;

  @Field(() => [RelationshipCommonInput], { nullable: true })
  relationship?: RelationshipCommonInput[];

  // MITRE Extension Fields
  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;

  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => [String], { nullable: true })
  x_mitre_domains?: string[];

  @Field(() => String, { nullable: true })
  x_mitre_version?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_aliases?: string[];
}

@InputType()
export class UpdateToolInput extends CreateToolInput {
  // Inherits all fields from CreateToolInput
}