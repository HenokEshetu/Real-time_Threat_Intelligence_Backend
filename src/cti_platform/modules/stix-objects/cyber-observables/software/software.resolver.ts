import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { SoftwareService } from './software.service';
import { Software } from './software.entity';
import { CreateSoftwareInput, UpdateSoftwareInput } from './software.input';

import { PartialType } from '@nestjs/graphql';
@InputType()
export class SearchSoftwareInput extends PartialType(CreateSoftwareInput) {}

@Resolver(() => Software)
export class SoftwareResolver {
  constructor(private readonly softwareService: SoftwareService) {}

  @Mutation(() => Software)
  async createSoftware(
    @Args('createSoftwareInput') createSoftwareInput: CreateSoftwareInput,
  ): Promise<Software> {
    return this.softwareService.create(createSoftwareInput);
  }

  


  // Search process dynamically using filters
    @Query(() => [Software], { name: 'software' })
    async searchSoftware(
      @Args('from', { type: () => Number, nullable: true }) from?: number,
      @Args('size', { type: () => Number, nullable: true }) size?: number,
      @Args('filter', { type: () => SearchSoftwareInput, nullable: true }) filter?: SearchSoftwareInput,
    ): Promise<Software[]> {
      return this.softwareService.searchWithFilters(from ?? 0, size ?? 10, filter ?? {});
    }

  @Query(() => Software)
  async software(@Args('id') id: string): Promise<Software> {
    return this.softwareService.findOne(id);
  }

  @Mutation(() => Software)
  async updateSoftware(
    @Args('id') id: string,
    @Args('updateSoftwareInput') updateSoftwareInput: UpdateSoftwareInput,
  ): Promise<Software> {
    return this.softwareService.update(id, updateSoftwareInput);
  }

  @Mutation(() => Boolean)
  async removeSoftware(@Args('id') id: string): Promise<boolean> {
    return this.softwareService.remove(id);
  }
}