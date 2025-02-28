import { Field, InputType } from '@nestjs/graphql';
import { LocationType, RelationshipCommonInput, RelationshipCommonProperties, CommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateLocationInput extends CommonInput {
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => LocationType)
  location_type: LocationType;

  @Field(() => String, { nullable: true })
  latitude?: string;

  @Field(() => String, { nullable: true })
  longitude?: string;

  @Field(() => String, { nullable: true })
  precision?: string;

  @Field(() => String, { nullable: true })
  region?: string;

  @Field(() => String, { nullable: true })
  country?: string;

  @Field(() => String, { nullable: true })
  administrative_area?: string;

  @Field(() => String, { nullable: true })
  city?: string;

  @Field(() => String, { nullable: true })
  street_address?: string;

  @Field(() => String, { nullable: true })
  postal_code?: string;

  @Field(() => [RelationshipCommonInput], { nullable: true })
     Relationship?: [RelationshipCommonProperties];

}

@InputType()
export class UpdateLocationInput extends CreateLocationInput{
  
}