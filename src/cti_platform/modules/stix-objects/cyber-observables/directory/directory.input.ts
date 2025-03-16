import { Field, InputType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';
@InputType()
export class CreateDirectoryInput extends CyberObservableCommonInput {
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

@InputType()
export class UpdateDirectoryInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  path?: string;

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