import { Field, ObjectType } from '@nestjs/graphql';

import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class Directory extends CyberObservableCommonProperties {
  @Field(() => String)
  
  path: string;

  @Field(() => String, { nullable: true })
  
  path_enc?: string;

  @Field(() => Date, { nullable: true })
  
  ctime?: Date;

  @Field(() => Date, { nullable: true })

  mtime?: Date;

  @Field(() => Date, { nullable: true })
 
  atime?: Date;

  @Field(() => Boolean, { nullable: true })
  
  contains_refs?: boolean;
}