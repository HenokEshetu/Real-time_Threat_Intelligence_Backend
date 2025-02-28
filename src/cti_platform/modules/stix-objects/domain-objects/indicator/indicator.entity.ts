import { Field, ObjectType } from '@nestjs/graphql';

import { CommonProperties, PatternType, RelationshipCommonProperties, IndicatorType, KillChainPhase } from '../../../../core/types/common-data-types';


@ObjectType()
export class Indicator extends CommonProperties {
  @Field(() => String)
  
  type: string = 'indicator';

  @Field(() => String)
  
  name: string;

  @Field(() => String, { nullable: true })
 
  description?: string;

  @Field(() => [IndicatorType], { nullable: true })
  
  indicator_types?: IndicatorType[];

  @Field(() => String)
  pattern: string;

  @Field(() => PatternType)
  default: PatternType.STIX
  pattern_type: PatternType;

  @Field(() => String, { nullable: true })
  
  pattern_version?: string;

  @Field(() => Date)
  valid_from: Date;

  @Field(() => Date, { nullable: true })
  valid_until?: Date;

  @Field(() => [KillChainPhase], { nullable: true })
  kill_chain_phases?: KillChainPhase[];


  @Field(() => [RelationshipCommonProperties], { nullable: true })
        relationship?: RelationshipCommonProperties[];
  }
