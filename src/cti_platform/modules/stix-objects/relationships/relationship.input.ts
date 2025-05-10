// relationship.input.ts
import { InputType, Field } from '@nestjs/graphql';
import { RelationshipCommonInput } from '../../../core/types/common-data-types';

@InputType()
export class CreateRelationshipInput extends RelationshipCommonInput {
  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_collection_layers?: string[];
}

@InputType()
export class UpdateRelationshipInput extends RelationshipCommonInput {
  @Field(() => String, { nullable: true })
  x_mitre_modified_by_ref?: string;

  @Field(() => Boolean, { nullable: true })
  x_mitre_deprecated?: boolean;

  @Field(() => String, { nullable: true })
  x_mitre_attack_spec_version?: string;

  @Field(() => [String], { nullable: true })
  x_mitre_collection_layers?: string[];
}