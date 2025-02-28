import { Field, InputType } from '@nestjs/graphql';
import { KillChainPhase, RelationshipCommonInput, RelationshipCommonProperties, 
  KillChainPhaseInput, CommonInput} from '../../../../core/types/common-data-types';

@InputType()
export class CreateIntrusionSetInput extends CommonInput{
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

  @Field(() => [KillChainPhaseInput], { nullable: true })
  kill_chain_phases?: KillChainPhase[];

  @Field(() => [RelationshipCommonInput], { nullable: true })
     Relationship?: [RelationshipCommonProperties];

}



@InputType()
export class UpdateIntrusionSetInput extends CreateIntrusionSetInput {
  
}