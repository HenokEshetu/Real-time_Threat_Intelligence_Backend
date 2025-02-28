import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { WindowsRegistryKeyService } from './windows-registry-key.service';
import { WindowsRegistryKey } from './windows-registry-key.entity';
import { CreateWindowsRegistryKeyInput, UpdateWindowsRegistryKeyInput } from './windows-registry-key.input';

import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchWindowsRegistryKeyInput extends PartialType(CreateWindowsRegistryKeyInput) {}


@Resolver(() => WindowsRegistryKey)
export class WindowsRegistryKeyResolver {
  constructor(private readonly windowsRegistryKeyService: WindowsRegistryKeyService) {}

  @Query(() => WindowsRegistryKey, { description: 'Search Windows Registry Keys with filters and pagination' })
  async searchWindowsRegistryKeys(
    @Args('searchParams', { type: () => SearchWindowsRegistryKeyInput, nullable: true }) searchParams?: Partial<SearchWindowsRegistryKeyInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number
  ): Promise<any> {
    return this.windowsRegistryKeyService.searchWithFilters(searchParams || {}, page, pageSize);
  }

  @Query(() => WindowsRegistryKey)
  async windowsRegistryKey(@Args('id') id: string): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.findOne(id);
  }

  @Mutation(() => WindowsRegistryKey)
  async createWindowsRegistryKey(
    @Args('createWindowsRegistryKeyInput') createWindowsRegistryKeyInput: CreateWindowsRegistryKeyInput,
  ): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.create(createWindowsRegistryKeyInput);
  }

  @Mutation(() => WindowsRegistryKey)
  async updateWindowsRegistryKey(
    @Args('id') id: string,
    @Args('updateWindowsRegistryKeyInput') updateWindowsRegistryKeyInput: UpdateWindowsRegistryKeyInput,
  ): Promise<WindowsRegistryKey> {
    return this.windowsRegistryKeyService.update(id, updateWindowsRegistryKeyInput);
  }

  @Mutation(() => Boolean)
  async removeWindowsRegistryKey(@Args('id') id: string): Promise<boolean> {
    return this.windowsRegistryKeyService.remove(id);
  }
}