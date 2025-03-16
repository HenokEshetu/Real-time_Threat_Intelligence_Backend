import { Field, ObjectType } from '@nestjs/graphql';

import { CyberObservableCommonProperties, Hashes } from '../../../../core/types/common-data-types';


@ObjectType()
export class X509Certificate extends CyberObservableCommonProperties {
  @Field(() => String)
  
  type: string = 'x509-certificate';

  @Field(() => Boolean, { nullable: true })
  
  is_self_signed?: boolean;

  @Field(() => Hashes, { nullable: true })
 
  hashes?: Hashes[];

  @Field(() => String, { nullable: true })
 
  version?: string;

  @Field(() => String, { nullable: true })
  
  serial_number?: string;

  @Field(() => String, { nullable: true })
  
  signature_algorithm?: string;

  @Field(() => String, { nullable: true })
  
  issuer?: string;

  @Field(() => Date, { nullable: true })
  
  validity_not_before?: Date;

  @Field(() => Date, { nullable: true })
 
  validity_not_after?: Date;

  @Field(() => String, { nullable: true })
 
  subject?: string;

  @Field(() => String, { nullable: true })
 
  subject_public_key_algorithm?: string;

  @Field(() => String, { nullable: true })
 
  subject_public_key_modulus?: string;

  @Field(() => String, { nullable: true })
 
  subject_public_key_exponent?: string;

  @Field(() => [String], { nullable: true })
  
  x509_v3_extensions?: string[];
}