import { Field, InputType } from '@nestjs/graphql';
import { PatternType, IndicatorType, RelationshipCommonInput, RelationshipCommonProperties, 
  KillChainPhaseInput, CommonInput, KillChainPhase } from '../../../../core/types/common-data-types';

@InputType()
export class CreateIndicatorInput extends CommonInput{
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [IndicatorType], { nullable: true })
  indicator_types?: IndicatorType[];

  @Field(() => String)
  pattern: string;

  @Field(() => PatternType)
  pattern_type: PatternType;

  @Field(() => String, { nullable: true })
  pattern_version?: string;

  @Field(() => Date)
  valid_from: Date;

  @Field(() => Date, { nullable: true })
  valid_until?: Date;


  @Field(() => [RelationshipCommonInput], { nullable: true })
     Relationship?: [RelationshipCommonProperties];

  @Field(() => [KillChainPhaseInput], { nullable: true })
  kill_chain_phases?: KillChainPhase[];
}


@InputType()
export class UpdateIndicatorInput extends CreateIndicatorInput {
  
}