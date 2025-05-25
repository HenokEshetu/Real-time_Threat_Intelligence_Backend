import { Field, InputType, Int, ObjectType, PartialType } from '@nestjs/graphql';
import {  CyberObservableCommonInput } from '../../../../core/types/common-data-types';
import { DomainName } from './domain-name.entity';

@InputType()
export class CreateDomainNameInput extends CyberObservableCommonInput {
  @Field(() => String)
  value: string;

  @Field(() => [String], { nullable: true })
  resolves_to_refs?: string[];
}

@InputType()
export class UpdateDomainNameInput extends CyberObservableCommonInput{
  @Field(() => String, { nullable: true })
  value?: string;

  @Field(() => [String], { nullable: true })
  resolves_to_refs?: string[];
}


@InputType()
export class DateRangeInput_domain_name {
  @Field(() => String, { nullable: true })
  gte?: string;

  @Field(() => String, { nullable: true })
  lte?: string;

  @Field(() => String, { nullable: true })
  gt?: string;

  @Field(() => String, { nullable: true })
  lt?: string;
}

@InputType()
export class SearchDomainNameInput extends PartialType(CreateDomainNameInput) {
  @Field(() => DateRangeInput_domain_name, { nullable: true })
  created_range?: DateRangeInput_domain_name;

  @Field(() => DateRangeInput_domain_name, { nullable: true })
  modified_range?: DateRangeInput_domain_name;
}

@ObjectType()
export class DomainNameSearchResult {
  @Field(() => Int)
  page: number;

  @Field(() => Int)
  pageSize: number;

  @Field(() => Int)
  total: number;

  @Field(() => Int)
  totalPages: number;

  @Field(() => [DomainName])
  results: DomainName[];
}