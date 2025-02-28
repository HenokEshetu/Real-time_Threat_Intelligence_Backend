import { Field, InputType } from '@nestjs/graphql';
import { IsString, IsOptional, Matches } from 'class-validator';
import { CyberObservableCommonInput } from '../../../../core/types/common-data-types';

@InputType()
export class CreateMACAddressInput extends CyberObservableCommonInput {
  @Field(() => String)
  @IsString()
  @Matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/, {
    message: 'Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX',
  })
  value: string;  // Make sure the field name doesn't contain dashes
}

@InputType()
export class UpdateMACAddressInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  @IsString()
  @IsOptional()
  @Matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/, {
    message: 'Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX',
  })
  value?: string;  // Similarly, avoid dashes in the field names
}
