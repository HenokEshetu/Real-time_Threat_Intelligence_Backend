import { Field, InputType } from '@nestjs/graphql';
import { CommonInput, RelationshipCommonProperties, RelationshipCommonInput} from '../../../../core/types/common-data-types';
@InputType()
export class CreateCampaignInput extends CommonInput {
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

  @Field(() => String, { nullable: true })
  objective?: string;

  @Field(() => [RelationshipCommonInput], { nullable: true })
    Relationship?: [RelationshipCommonProperties];
  
}

@InputType()
export class UpdateCampaignInput extends CreateCampaignInput{
  
}