import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
class EmailMIMEComponentInput extends CyberObservableCommonInput {
  @Field(() => String)
  body: string;

  @Field(() => String, { nullable: true })
  body_raw_ref?: string;

  @Field(() => String, { nullable: true })
  content_type?: string;

  @Field(() => String, { nullable: true })
  content_disposition?: string;
}

@InputType()
export class CreateEmailMessageInput extends CyberObservableCommonInput {
  @Field(() => Boolean, { nullable: true })
  is_multipart?: boolean;

  @Field(() => Date, { nullable: true })
  date?: Date;

  @Field(() => String, { nullable: true })
  content_type?: string;

  @Field(() => String, { nullable: true })
  from_ref?: string;

  @Field(() => [String], { nullable: true })
  sender_ref?: string[];

  @Field(() => [String], { nullable: true })
  to_refs?: string[];

  @Field(() => [String], { nullable: true })
  cc_refs?: string[];

  @Field(() => [String], { nullable: true })
  bcc_refs?: string[];

  @Field(() => String, { nullable: true })
  message_id?: string;

  @Field(() => String, { nullable: true })
  subject?: string;

  @Field(() => [String], { nullable: true })
  received_lines?: string[];

  @Field(() => String, { nullable: true })
  body?: string;

  @Field(() => [EmailMIMEComponentInput], { nullable: true })
  body_multipart?: EmailMIMEComponentInput[];

  @Field(() => String, { nullable: true })
  raw_email_ref?: string;
}

@InputType()
export class UpdateEmailMessageInput extends CreateEmailMessageInput {}