import { Field, InputType, Int } from '@nestjs/graphql';
import { CommonInput, Dictionary } from 'src/cti_platform/core/types/common-data-types';
@InputType()
export class CreateSightingInput extends CommonInput {
  @Field(() => String)
  sighting_of_ref: string;
  @Field(() => String)
  @Field(() => String)
  @Field(() => [String], { nullable: true })
  observed_data_refs?: string[];
  @Field(() => [String], { nullable: true })
  where_sighted_refs?: string[];
  @Field(() => String, { nullable: true })
  summary?: string;
  @Field(() => Date)
  first_seen: string;
  @Field(() => Date)
  last_seen: string;
  @Field(() => Int, { nullable: true })
  count?: number;
  @Field(() => Boolean, { nullable: true })
  detected?: boolean;
  @Field(() => String, { nullable: true })
  extensions?: Dictionary;
}

@InputType()
export class UpdateSightingInput extends CreateSightingInput {
  
}