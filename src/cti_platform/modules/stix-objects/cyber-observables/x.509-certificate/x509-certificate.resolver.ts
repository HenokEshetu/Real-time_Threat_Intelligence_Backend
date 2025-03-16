import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { X509CertificateService } from './x509-certificate.service';
import { X509Certificate } from './x509-certificate.entity';
import { CreateX509CertificateInput, UpdateX509CertificateInput } from './x509-certificate.input';

import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchX509CertificateInput extends PartialType(CreateX509CertificateInput) {}




@Resolver(() => X509Certificate)
export class X509CertificateResolver {
  constructor(private readonly x509CertificateService: X509CertificateService) {}

  @Mutation(() => X509Certificate)
  async createX509Certificate(
    @Args('createX509CertificateInput') createX509CertificateInput: CreateX509CertificateInput,
  ): Promise<X509Certificate> {
    return this.x509CertificateService.create(createX509CertificateInput);
  }

  @Query(() => [X509Certificate])
  async x509Certificates(): Promise<X509Certificate[]> {
    return this.x509CertificateService.searchWithFilters();
  }

@Query(() => X509Certificate, { description: 'Search Windows Registry Keys with filters and pagination' })
  async searchWindowsRegistryKeys(
    @Args('searchParams', { type: () =>  SearchX509CertificateInput, nullable: true }) searchParams?: Partial< SearchX509CertificateInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number
  ): Promise<any> {
    return this.x509CertificateService.searchWithFilters(searchParams || {}, page, pageSize);
  }




  @Query(() => X509Certificate)
  async x509Certificate(@Args('id') id: string): Promise<X509Certificate> {
    return this.x509CertificateService.findOne(id);
  }

  @Mutation(() => X509Certificate)
  async updateX509Certificate(
    @Args('id') id: string,
    @Args('updateX509CertificateInput') updateX509CertificateInput: UpdateX509CertificateInput,
  ): Promise<X509Certificate> {
    return this.x509CertificateService.update(id, updateX509CertificateInput);
  }

  @Mutation(() => Boolean)
  async removeX509Certificate(@Args('id') id: string): Promise<boolean> {
    return this.x509CertificateService.remove(id);
  }
}