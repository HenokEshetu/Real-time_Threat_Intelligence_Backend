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
import { WindowsRegistryKeyService } from './windows-registry-key.service';
import { WindowsRegistryKey } from './windows-registry-key.entity';
import {
  CreateWindowsRegistryKeyInput,
  UpdateWindowsRegistryKeyInput,
} from './windows-registry-key.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchWindowsRegistryKeyInput extends PartialType(
  CreateWindowsRegistryKeyInput,
) {}

@ObjectType()
export class WindowsRegistryKeySearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [WindowsRegistryKey])
  results: WindowsRegistryKey[];
}

@Resolver(() => WindowsRegistryKey)
export class WindowsRegistryKeyResolver extends BaseStixResolver(
  WindowsRegistryKey,
) {
  public typeName = ' windows-registry-key';
  constructor(
    private readonly windowsRegistryKeyService: WindowsRegistryKeyService,
  ) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => WindowsRegistryKey)
  async createWindowsRegistryKey(
    @Args('input') createWindowsRegistryKeyInput: CreateWindowsRegistryKeyInput,
  ): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.create(createWindowsRegistryKeyInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => WindowsRegistryKeySearchResult)
  async searchWindowsRegistryKeys(
    @Args('filters', {
      type: () => SearchWindowsRegistryKeyInput,
      nullable: true,
    })
    filters: SearchWindowsRegistryKeyInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<WindowsRegistryKeySearchResult> {
    return this.windowsRegistryKeyService.searchWithFilters(
      filters,
      page,
      pageSize,
    );
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => WindowsRegistryKey, { nullable: true })
  async windowsRegistryKey(
    @Args('id') id: string,
  ): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => WindowsRegistryKey)
  async updateWindowsRegistryKey(
    @Args('id') id: string,
    @Args('input') updateWindowsRegistryKeyInput: UpdateWindowsRegistryKeyInput,
  ): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.update(
      id,
      updateWindowsRegistryKeyInput,
    );
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteWindowsRegistryKey(@Args('id') id: string): Promise<boolean> {
    return this.windowsRegistryKeyService.remove(id);
  }
}
