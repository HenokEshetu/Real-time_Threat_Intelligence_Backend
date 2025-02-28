import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';
@InputType()
export class CreateNetworkTrafficInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  start?: string;

  @Field(() => String, { nullable: true })
  end?: string;

  @Field(() => Boolean, { nullable: true })
  is_active?: boolean;

  @Field(() => String, { nullable: true })
  src_ref?: string;

  @Field(() => String, { nullable: true })
  dst_ref?: string;

  @Field(() => Number, { nullable: true })
  src_port?: number;

  @Field(() => Number, { nullable: true })
  dst_port?: number;

  @Field(() => [String], { nullable: true })
  protocols?: string[];

  @Field(() => Number, { nullable: true })
  src_byte_count?: number;

  @Field(() => Number, { nullable: true })
  dst_byte_count?: number;

  @Field(() => Number, { nullable: true })
  src_packets?: number;

  @Field(() => Number, { nullable: true })
  dst_packets?: number;

  @Field(() => Boolean, { nullable: true })
  ipfix?: boolean;

  @Field(() => String, { nullable: true })
  src_payload_ref?: string;

  @Field(() => String, { nullable: true })
  dst_payload_ref?: string;

  @Field(() => [String], { nullable: true })
  encapsulates_refs?: string[];

  @Field(() => String, { nullable: true })
  encapsulated_by_ref?: string;
}

@InputType()
export class UpdateNetworkTrafficInput extends CyberObservableCommonInput{
  @Field(() => String, { nullable: true })
  start?: string;

  @Field(() => String, { nullable: true })
  end?: string;

  @Field(() => Boolean, { nullable: true })
  is_active?: boolean;

  @Field(() => String, { nullable: true })
  src_ref?: string;

  @Field(() => String, { nullable: true })
  dst_ref?: string;

  @Field(() => Number, { nullable: true })
  src_port?: number;

  @Field(() => Number, { nullable: true })
  dst_port?: number;

  @Field(() => [String], { nullable: true })
  protocols?: string[];

  @Field(() => Number, { nullable: true })
  src_byte_count?: number;

  @Field(() => Number, { nullable: true })
  dst_byte_count?: number;

  @Field(() => Number, { nullable: true })
  src_packets?: number;

  @Field(() => Number, { nullable: true })
  dst_packets?: number;

  @Field(() => Boolean, { nullable: true })
  ipfix?: boolean;

  @Field(() => String, { nullable: true })
  src_payload_ref?: string;

  @Field(() => String, { nullable: true })
  dst_payload_ref?: string;

  @Field(() => [String], { nullable: true })
  encapsulates_refs?: string[];

  @Field(() => String, { nullable: true })
  encapsulated_by_ref?: string;
}