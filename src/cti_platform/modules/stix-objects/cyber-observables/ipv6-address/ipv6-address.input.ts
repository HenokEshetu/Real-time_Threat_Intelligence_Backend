import { Field, InputType } from '@nestjs/graphql';
import { IsString, IsOptional, IsIP } from 'class-validator';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateIPv6AddressInput extends  CyberObservableCommonInput {
  @Field(() => String)
  @IsString()
  @IsIP(6)
  value: string;

  @Field(() => String, { nullable: true })
  @IsString()
  @IsOptional()
  resolves_to_refs?: string;
}

@InputType()
export class UpdateIPv6AddressInput extends  CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  @IsString()
  @IsIP(6)
  @IsOptional()
  value?: string;

  @Field(() => String, { nullable: true })
  @IsString()
  @IsOptional()
  resolves_to_refs?: string;
}