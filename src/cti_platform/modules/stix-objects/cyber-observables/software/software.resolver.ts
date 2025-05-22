import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
  ObjectType,
  Field,
  PartialType,
} from '@nestjs/graphql';
import { SoftwareService } from './software.service';
import { Software } from './software.entity';
import { CreateSoftwareInput, UpdateSoftwareInput } from './software.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchSoftwareInput extends PartialType(CreateSoftwareInput) {}

@ObjectType()
export class SoftwareSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Software])
  results: Software[];
}

@Resolver(() => Software)
export class SoftwareResolver extends BaseStixResolver(Software) {
  public typeName = ' software';
  constructor(private readonly softwareService: SoftwareService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => Software)
  async createSoftware(
    @Args('input') createSoftwareInput: CreateSoftwareInput,
  ): Promise<Software> {
    return this.softwareService.create(createSoftwareInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => SoftwareSearchResult)
  async searchSoftware(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchSoftwareInput, nullable: true })
    filters: SearchSoftwareInput = {},
  ): Promise<SoftwareSearchResult> {
    return this.softwareService.searchWithFilters(from, size, filters);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => Software, { nullable: true })
  async software(@Args('id') id: string): Promise<Software> {
    return this.softwareService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => Software)
  async updateSoftware(
    @Args('id') id: string,
    @Args('input') updateSoftwareInput: UpdateSoftwareInput,
  ): Promise<Software> {
    return this.softwareService.update(id, updateSoftwareInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteSoftware(@Args('id') id: string): Promise<boolean> {
    return this.softwareService.remove(id);
  }
}
