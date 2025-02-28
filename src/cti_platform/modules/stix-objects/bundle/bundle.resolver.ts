import { Resolver,InputType, Query, Int, Mutation, Args } from '@nestjs/graphql';
import { BundleService } from './bundle.service';
import { Bundle } from './bundle.entity';
import { CreateBundleInput, UpdateBundleInput } from './bundle.input';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchBundleInput extends PartialType(CreateBundleInput) {}

@Resolver(() => Bundle)
export class BundleResolver {
  constructor(private readonly bundleService: BundleService) {}

  @Mutation(() => Bundle)
  async createBundle(
    @Args('createBundleInput') createBundleInput: CreateBundleInput,
  ): Promise<Bundle> {
    return this.bundleService.create(createBundleInput);
  }

  @Query(() => [Bundle])
    async serchBundle(
      @Args('searchParams', { type: () => SearchBundleInput, nullable: true }) searchParams?: SearchBundleInput,
      @Args('page', { type: () => Int, defaultValue: 1 }) page?: number,
      @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize?: number
    ): Promise<Bundle[]> {
      const from = (page - 1) * pageSize;
      const result = await this.bundleService.searchWithFilters(searchParams || {}, from, pageSize);
      return result.results;
    }

  @Query(() => Bundle)
  async bundle(@Args('id') id: string): Promise<Bundle> {
    return this.bundleService.findOne(id);
  }

  @Mutation(() => Bundle)
  async updateBundle(
    @Args('id') id: string,
    @Args('updateBundleInput') updateBundleInput: UpdateBundleInput,
  ): Promise<Bundle> {
    return this.bundleService.update(id, updateBundleInput);
  }

  @Mutation(() => Boolean)
  async removeBundle(@Args('id') id: string): Promise<boolean> {
    return this.bundleService.remove(id);
  }
}