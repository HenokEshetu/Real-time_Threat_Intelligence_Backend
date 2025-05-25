import { Field, ObjectType } from '@nestjs/graphql';
import { CyberObservableCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class DomainName extends CyberObservableCommonProperties {
  @Field(() => String)
  
  value: string;

  @Field(() => [String], { nullable: true })
  
  resolves_to_refs?: string[];
}