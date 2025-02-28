import { Field, ObjectType } from '@nestjs/graphql';
import { Entity, Column } from 'typeorm';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class UserAccount extends CyberObservableCommonProperties {
  @Field(() => String)
  
  type: string = 'user-account';

  @Field(() => String, { nullable: true })
  
  user_id?: string;

  @Field(() => String, { nullable: true })
 
  credential?: string;

  @Field(() => String, { nullable: true })
  
  account_login?: string;

  @Field(() => String, { nullable: true })
 
  account_type?: string;

  @Field(() => String, { nullable: true })
  
  display_name?: string;

  @Field(() => Boolean, { nullable: true })
  
  is_service_account?: boolean;

  @Field(() => Boolean, { nullable: true })
 
  is_privileged?: boolean;

  @Field(() => Boolean, { nullable: true })
 
  can_escalate_privs?: boolean;

  @Field(() => Boolean, { nullable: true })
  
  is_disabled?: boolean;

  @Field(() => String, { nullable: true })
  
  account_created?: string;

  @Field(() => String, { nullable: true })
  
  account_expires?: string;

  @Field(() => String, { nullable: true })
 
  credential_last_changed?: string;

  @Field(() => String, { nullable: true })

  account_first_login?: string;

  @Field(() => String, { nullable: true })
  
  account_last_login?: string;
}