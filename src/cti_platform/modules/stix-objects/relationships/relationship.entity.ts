// relationship.entity.ts
import { ObjectType, Field } from '@nestjs/graphql';
import { RelationshipCommonProperties } from '../../../core/types/common-data-types';

@ObjectType()
export class StixRelationship extends RelationshipCommonProperties {
  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_collection_layers?: string[];
}