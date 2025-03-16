import { Field, ObjectType } from '@nestjs/graphql';

import { CyberObservableCommonProperties, Hashes } from '../../../../core/types/common-data-types';


@ObjectType()
export class Artifact extends CyberObservableCommonProperties {
  @Field(() => String)
 
  type: string = 'artifact';

  @Field(() => String, { nullable: true })

  mime_type?: string;

  @Field(() => String, { nullable: true })
 
  payload_bin?: string;

  @Field(() => String, { nullable: true })
  
  url?: string;

  @Field(() => Hashes, { nullable: true })
 
  hashes?: Hashes[];

  @Field(() => Number, { nullable: true })
 
  encryption_algorithm?: number;

  @Field(() => String, { nullable: true })
  
  decryption_key?: string;
}