import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { X509CertificateService } from './x509-certificate.service';
import { X509Certificate } from './x509-certificate.entity';
import { CreateX509CertificateInput, UpdateX509CertificateInput } from './x509-certificate.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

@InputType()
export class SearchX509CertificateInput extends PartialType(CreateX509CertificateInput) {}

@ObjectType()
export class X509CertificateSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [X509Certificate])
  results: X509Certificate[];
}

@Resolver(() => X509Certificate)
export class X509CertificateResolver extends BaseStixResolver(X509Certificate) {
  public typeName = ' x509-certificate';
  constructor(private readonly x509CertificateService: X509CertificateService) {
    super()
  }

  @Mutation(() => X509Certificate)
  async createX509Certificate(
    @Args('input') createX509CertificateInput: CreateX509CertificateInput,
  ): Promise<X509Certificate> {
    return this.x509CertificateService.create(createX509CertificateInput);
  }

  @Query(() => X509CertificateSearchResult)
  async searchX509Certificates(
    @Args('filters', { type: () => SearchX509CertificateInput, nullable: true }) filters: SearchX509CertificateInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<X509CertificateSearchResult> {
    return this.x509CertificateService.searchWithFilters(filters, from, size);
  }

  @Query(() => X509Certificate, { nullable: true })
  async x509Certificate(@Args('id') id: string): Promise<X509Certificate> {
    return this.x509CertificateService.findOne(id);
  }

  @Mutation(() => X509Certificate)
  async updateX509Certificate(
    @Args('id') id: string,
    @Args('input') updateX509CertificateInput: UpdateX509CertificateInput,
  ): Promise<X509Certificate> {
    return this.x509CertificateService.update(id, updateX509CertificateInput);
  }

  @Mutation(() => Boolean)
  async deleteX509Certificate(@Args('id') id: string): Promise<boolean> {
    return this.x509CertificateService.remove(id);
  }
}