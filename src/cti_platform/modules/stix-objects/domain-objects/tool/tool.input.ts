import { Field, InputType } from '@nestjs/graphql';
import { ToolType, KillChainPhaseInput, CommonInput, RelationshipCommonInput,RelationshipCommonProperties, KillChainPhase } from '../../../../core/types/common-data-types';

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
  Relationship?: [RelationshipCommonProperties];


}



@InputType()
export class UpdateToolInput extends CreateToolInput {
  
}