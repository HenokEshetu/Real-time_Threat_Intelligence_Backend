import { Field, ObjectType } from '@nestjs/graphql';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';

@ObjectType()

class WindowsRegistryValue {
  @Field(() => String, { nullable: true })
  
  name?: string;

  @Field(() => String, { nullable: true })
  
  data?: string;

  @Field(() => String, { nullable: true })
  
  data_type?: string;
}


@ObjectType()
export class WindowsRegistryKey extends CyberObservableCommonProperties {
  @Field(() => String)
 
  type: string = 'windows-registry-key';

  @Field(() => String, { nullable: true })
  
  key?: string;

  @Field(() => [WindowsRegistryValue], { nullable: true })
 
  values?: WindowsRegistryValue[];

  @Field(() => String, { nullable: true })
  
  modified_time?: string;

  @Field(() => String, { nullable: true })
  
  creator_user_ref?: string;

  @Field(() => String, { nullable: true })

  number_of_subkeys?: string;
}