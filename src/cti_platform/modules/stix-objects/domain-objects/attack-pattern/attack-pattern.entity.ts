import { Field, ObjectType } from '@nestjs/graphql';

import { CommonProperties, KillChainPhase, } from '../../../../core/types/common-data-types';
import { RelationshipCommonProperties } from '../../../../core/types/common-data-types';

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
  }
