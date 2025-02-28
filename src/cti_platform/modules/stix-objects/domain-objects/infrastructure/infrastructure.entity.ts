import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties,RelationshipCommonProperties, InfrastructureType, KillChainPhase } from '../../../../core/types/common-data-types';

@ObjectType()
export class Infrastructure extends CommonProperties {
  @Field(() => String)
  type: string = 'infrastructure';

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

  @Field(() => [KillChainPhase], { nullable: true })
  kill_chain_phases?: KillChainPhase[];
  
  @Field(() => [RelationshipCommonProperties], { nullable: true })
      relationship?: RelationshipCommonProperties[];
}