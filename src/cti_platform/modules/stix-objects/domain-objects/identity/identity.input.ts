import { Field, InputType } from '@nestjs/graphql';
import { IdentityClass, CommonInput, RelationshipCommonInput,RelationshipCommonProperties, IndustrySector } from '../../../../core/types/common-data-types';

@InputType()
export class CreateIdentityInput extends CommonInput{
  @Field(() => String)
  name: string;

  @Field(() => String, { nullable: true })
  description?: string;

  @Field(() => [String], { nullable: true })
  roles?: string[];

  @Field(() => IdentityClass)
  identity_class: IdentityClass;

  @Field(() => [IndustrySector], { nullable: true })
  sectors?: IndustrySector[];

  @Field(() => String, { nullable: true })
  contact_information?: string;

  @Field(() => [RelationshipCommonInput], { nullable: true })
   Relationship?: [RelationshipCommonProperties];
}

@InputType()
export class UpdateIdentityInput extends CreateIdentityInput {
  
}