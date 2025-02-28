import { Field, InputType } from '@nestjs/graphql';
import { KillChainPhase, RelationshipCommonInput, RelationshipCommonProperties, KillChainPhaseInput, CommonInput} from '../../../../core/types/common-data-types';

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
  Relationship?: [RelationshipCommonProperties];

}



@InputType()
export class UpdateAttackPatternInput extends CreateAttackPatternInput {
  
}