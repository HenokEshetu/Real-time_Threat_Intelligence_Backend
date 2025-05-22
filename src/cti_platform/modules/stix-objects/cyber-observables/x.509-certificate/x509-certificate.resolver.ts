import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
  PartialType,
  ObjectType,
  Field,
} from '@nestjs/graphql';
import { X509CertificateService } from './x509-certificate.service';
import { X509Certificate } from './x509-certificate.entity';
import {
  CreateX509CertificateInput,
  UpdateX509CertificateInput,
} from './x509-certificate.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchX509CertificateInput extends PartialType(
  CreateX509CertificateInput,
) {}

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
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => X509Certificate)
  async createX509Certificate(
    @Args('input') createX509CertificateInput: CreateX509CertificateInput,
  ): Promise<X509Certificate> {
    return this.x509CertificateService.create(createX509CertificateInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => X509CertificateSearchResult)
  async searchX509Certificates(
    @Args('filters', { type: () => SearchX509CertificateInput, nullable: true })
    filters: SearchX509CertificateInput = {},
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
  ): Promise<X509CertificateSearchResult> {
    return this.x509CertificateService.searchWithFilters(filters, from, size);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => X509Certificate, { nullable: true })
  async x509Certificate(@Args('id') id: string): Promise<X509Certificate> {
    return this.x509CertificateService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => X509Certificate)
  async updateX509Certificate(
    @Args('id') id: string,
    @Args('input') updateX509CertificateInput: UpdateX509CertificateInput,
  ): Promise<X509Certificate> {
    return this.x509CertificateService.update(id, updateX509CertificateInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteX509Certificate(@Args('id') id: string): Promise<boolean> {
    return this.x509CertificateService.remove(id);
  }
}
