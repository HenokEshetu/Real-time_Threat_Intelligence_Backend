// tool.entity.ts
import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties, ToolType, KillChainPhase } from '../../../../core/types/common-data-types';

@ObjectType()
export class Tool extends CommonProperties {
  @Field(() => String)
  type: string = 'tool';

  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [ToolType])
  tool_types: ToolType[];

  @Field(() => [String], { nullable: true })
  aliases?: string[];

  @Field(() => [KillChainPhase], { nullable: true })
  kill_chain_phases?: KillChainPhase[];

  @Field(() => String, { nullable: true })
  tool_version?: string;

  @Field(() => [RelationshipCommonProperties], { nullable: true })
  relationship?: RelationshipCommonProperties[];

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