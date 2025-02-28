import { Field, ObjectType } from '@nestjs/graphql';
import GraphQLJSON from 'graphql-type-json';
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';
import { CyberObservableCommonProperties, Dictionary } from '../../../../core/types/common-data-types';

@ObjectType()
class EmailMIMEComponent {
  @Field(() => String)
  body: string;

  @Field(() => String)
  body_raw_ref?: string;

  @Field(() => String)
  content_type?: string;

  @Field(() => String)
  content_disposition?: string;
}


@ObjectType()
export class EmailMessage extends CyberObservableCommonProperties {
  @Field(() => String, { nullable: true })
  
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

  @Field(() => GraphQLJSON, { nullable: true })
  
  additional_header_fields?: Dictionary;

  @Field(() => String, { nullable: true })
 
  body?: string;

  @Field(() => String, { nullable: true })
 
  body_multipart?: EmailMIMEComponent[];

  @Field(() => String, { nullable: true })
 
  raw_email_ref?: string;
}