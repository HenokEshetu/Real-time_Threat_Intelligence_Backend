import { Field, InputType, Int, ObjectType, PartialType } from '@nestjs/graphql';
import { KillChainPhase, RelationshipCommonInput, RelationshipCommonProperties, 
  KillChainPhaseInput, CommonInput} from '../../../../core/types/common-data-types';
import { IntrusionSet } from './intrusion-set.entity';

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

     // MITRE Extension Fields
  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => [String], { nullable: true })
  x_mitre_domains?: string[];

  @Field(() => String, { nullable: true })
  x_mitre_version?: string;

  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;

 

}



@InputType()
export class UpdateIntrusionSetInput extends CreateIntrusionSetInput {
  
}



@InputType()
export class DateRangeInput_intrusion_set {
  @Field(() => String, { nullable: true })
  gte?: string;

  @Field(() => String, { nullable: true })
  lte?: string;

  @Field(() => String, { nullable: true })
  gt?: string;

  @Field(() => String, { nullable: true })
  lt?: string;
}

@InputType()
export class SearchIntrusionSetInput extends PartialType(CreateIntrusionSetInput) {
  @Field(() => DateRangeInput_intrusion_set, { nullable: true })
  first_seen_range?: DateRangeInput_intrusion_set;

  @Field(() => DateRangeInput_intrusion_set, { nullable: true })
  last_seen_range?: DateRangeInput_intrusion_set;
}

@ObjectType()
export class IntrusionSetSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [IntrusionSet])
  results: IntrusionSet[];
}