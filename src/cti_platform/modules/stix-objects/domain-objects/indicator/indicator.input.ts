import { Field, InputType, Int, ObjectType, PartialType } from '@nestjs/graphql';
import { PatternType, IndicatorType, RelationshipCommonInput, RelationshipCommonProperties, 
  KillChainPhaseInput, CommonInput, KillChainPhase } from '../../../../core/types/common-data-types';
import { Indicator } from './indicator.entity';

@InputType()
export class CreateIndicatorInput extends CommonInput{
  @Field(() => String)
  name?: string;
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
  @Field(() => Date, { nullable: true })
  valid_from?: Date;
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
@InputType()
export class DateRangeInput {
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
export class SearchIndicatorInput extends PartialType(CreateIndicatorInput) {
  @Field(() => DateRangeInput, { nullable: true })
  valid_from_range?: DateRangeInput;

  @Field(() => DateRangeInput, { nullable: true })
  valid_until_range?: DateRangeInput;
}

@ObjectType()
export class IndicatorSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Indicator])
  results: Indicator[];
}

