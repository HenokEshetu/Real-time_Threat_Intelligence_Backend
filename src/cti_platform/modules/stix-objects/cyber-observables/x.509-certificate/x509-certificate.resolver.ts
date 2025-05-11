import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { X509CertificateService } from './x509-certificate.service';
import { X509Certificate } from './x509-certificate.entity';
import { CreateX509CertificateInput, UpdateX509CertificateInput } from './x509-certificate.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchX509CertificateInput extends PartialType(CreateX509CertificateInput) { }

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
export class X509CertificateResolver {
  
  constructor(
    private readonly x509CertificateService: X509CertificateService,
    @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
  ) { }

  // Date conversion helper
  public convertDates(payload: any): X509Certificate {
    const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
    dateFields.forEach(field => {
      if (payload[field]) payload[field] = new Date(payload[field]);
    });
    return payload;
  }

  // Subscription Definitions
  @Subscription(() => X509Certificate, {
    name: 'x509CertificateCreated',
    resolve: (payload) => payload,
  })
  x509CertificateCreated() {
    return this.pubSub.asyncIterator('x509CertificateCreated');
  }

  @Subscription(() => X509Certificate, {
    name: 'x509CertificateUpdated',
    resolve: (payload) => payload,
  })
  x509CertificateUpdated() {
    return this.pubSub.asyncIterator('x509CertificateUpdated');
  }

  @Subscription(() => String, { name: 'x509CertificateDeleted' })
  x509CertificateDeleted() {
    return this.pubSub.asyncIterator('x509CertificateDeleted');
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