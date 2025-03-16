import { Field, InputType } from '@nestjs/graphql';
import { Hashes, HashesInput,  CyberObservableCommonInput } from '../../../../core/types/common-data-types';
@InputType()
export class CreateArtifactInput extends CyberObservableCommonInput {
  @Field(() => String, { nullable: true })
  mime_type?: string;

  @Field(() => String, { nullable: true })
  payload_bin?: string;

  @Field(() => String, { nullable: true })
  url?: string;

  @Field(() => HashesInput, { nullable: true })
  hashes?:HashesInput[];

  @Field(() => Number, { nullable: true })
  encryption_algorithm?: number;

  @Field(() => String, { nullable: true })
  decryption_key?: string;
}

@InputType()
export class UpdateArtifactInput extends CreateArtifactInput {
  
}