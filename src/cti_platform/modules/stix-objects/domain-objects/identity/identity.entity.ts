import { Field, ObjectType } from '@nestjs/graphql';
import { CommonProperties,RelationshipCommonProperties, IdentityClass, IndustrySector } from '../../../../core/types/common-data-types';

@ObjectType()
export class Identity extends CommonProperties {
  @Field(() => String)
  type: string = 'identity';

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
  
  @Field(() => [RelationshipCommonProperties], { nullable: true })
      relationship?: RelationshipCommonProperties[];

}
