import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput, HashesInput } from '../../../../core/types/common-data-types';


@InputType()
export class CreateX509CertificateInput extends CyberObservableCommonInput{
  @Field(() => Boolean, { nullable: true })
  is_self_signed?: boolean;

  @Field(() => HashesInput, { nullable: true })
  hashes?: HashesInput[];

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

@InputType()
export class UpdateX509CertificateInput extends CreateX509CertificateInput{
  
}