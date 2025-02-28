import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties, RelationshipCommonProperties, LocationType } from '../../../../core/types/common-data-types';


@ObjectType()
export class Location extends CommonProperties {
  @Field(() => String)
  type: string = 'location';

  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => LocationType)
  default: LocationType.UNKNOWN
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

  @Field(() => [RelationshipCommonProperties], { nullable: true })
  relationship?: RelationshipCommonProperties[];

}