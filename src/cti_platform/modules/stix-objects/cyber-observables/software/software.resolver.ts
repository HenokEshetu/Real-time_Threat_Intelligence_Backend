import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { SoftwareService } from './software.service';
import { Software } from './software.entity';
import { CreateSoftwareInput, UpdateSoftwareInput } from './software.input';

import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
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
export class SoftwareResolver {
  constructor(private readonly softwareService: SoftwareService) {}

  @Mutation(() => Software)
  async createSoftware(
    @Args('input') createSoftwareInput: CreateSoftwareInput,
  ): Promise<Software> {
    return this.softwareService.create(createSoftwareInput);
  }

  @Query(() => SoftwareSearchResult)
  async searchSoftware(
    @Args('from', { type: () => Int, defaultValue: 0 }) from: number,
    @Args('size', { type: () => Int, defaultValue: 10 }) size: number,
    @Args('filters', { type: () => SearchSoftwareInput, nullable: true }) filters: SearchSoftwareInput = {},
  ): Promise<SoftwareSearchResult> {
    return this.softwareService.searchWithFilters(from, size, filters);
  }

  @Query(() => Software, { nullable: true })
  async software(@Args('id') id: string): Promise<Software> {
    return this.softwareService.findOne(id);
  }

  @Mutation(() => Software)
  async updateSoftware(
    @Args('id') id: string,
    @Args('input') updateSoftwareInput: UpdateSoftwareInput,
  ): Promise<Software> {
    return this.softwareService.update(id, updateSoftwareInput);
  }

  @Mutation(() => Boolean)
  async deleteSoftware(@Args('id') id: string): Promise<boolean> {
    return this.softwareService.remove(id);
  }
}