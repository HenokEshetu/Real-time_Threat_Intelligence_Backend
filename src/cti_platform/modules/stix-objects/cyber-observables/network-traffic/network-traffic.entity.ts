import { Field, ObjectType } from '@nestjs/graphql';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class NetworkTraffic extends CyberObservableCommonProperties {
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

  @Field(() => String, { nullable: true })
 
  src_port?: number;

  @Field(() => String, { nullable: true })
  
  dst_port?: number;

  @Field(() => [String], { nullable: true })
  
  protocols?: string[];

  @Field(() => String, { nullable: true })
  
  src_byte_count?: number;

  @Field(() => String, { nullable: true })
 
  dst_byte_count?: number;

  @Field(() => String, { nullable: true })
  
  src_packets?: number;

  @Field(() => String, { nullable: true })
  
  dst_packets?: number;

  @Field(() => Boolean, { nullable: true })
 
  ipfix?: boolean;

  @Field(() => String, { nullable: true })
 
  src_payload_ref?: string;

  @Field(() => String, { nullable: true })
 
  dst_payload_ref?: string;

  @Field(() => String, { nullable: true })
 
  encapsulates_refs?: string[];

  @Field(() => String, { nullable: true })
  
  encapsulated_by_ref?: string;
}