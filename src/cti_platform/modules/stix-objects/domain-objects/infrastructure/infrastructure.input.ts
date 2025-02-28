import { Field, InputType } from '@nestjs/graphql';
import { InfrastructureType,RelationshipCommonProperties, RelationshipCommonInput, 
  CommonInput,KillChainPhaseInput, KillChainPhase } from '../../../../core/types/common-data-types';

@InputType()
export class CreateInfrastructureInput extends CommonInput {
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [InfrastructureType], { nullable: true })
  infrastructure_types?: InfrastructureType[];

  @Field(() => [String], { nullable: true })
  aliases?: string[];

  @Field(() => Date, { nullable: true })
  first_seen?: Date;

  @Field(() => Date, { nullable: true })
  last_seen?: Date;

  @Field(() => [KillChainPhaseInput], { nullable: true })
  kill_chain_phases?: KillChainPhase[];

  @Field(() => [RelationshipCommonInput], { nullable: true })
     Relationship?: [RelationshipCommonProperties];


}


@InputType()
export class UpdateInfrastructureInput extends CreateInfrastructureInput {
  
}