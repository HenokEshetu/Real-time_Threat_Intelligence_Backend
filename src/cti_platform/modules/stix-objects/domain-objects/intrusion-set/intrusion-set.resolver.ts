import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { IntrusionSetService } from './intrusion-set.service';
import { CreateIntrusionSetInput, UpdateIntrusionSetInput } from './intrusion-set.input';
import { IntrusionSet } from './intrusion-set.entity';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchIntrusionSetInput extends PartialType(CreateIntrusionSetInput){}



@Resolver('IntrusionSet')
export class IntrusionSetResolver {
  constructor(private readonly intrusionSetService: IntrusionSetService) {}

  @Mutation(() => IntrusionSet)
  async createIntrusionSet(
    @Args('createIntrusionSetInput') createIntrusionSetInput: CreateIntrusionSetInput,
  ) {
    const result = await this.intrusionSetService.create(createIntrusionSetInput);
    return result.id;
  }

  @Query(() => IntrusionSet, { nullable: true })
  async getIntrusionSet(@Args('id') id: string) {
    return this.intrusionSetService.findOne(id);
  }

  @Mutation(() => IntrusionSet)
  async updateIntrusionSet(
    @Args('id') id: string,
    @Args('updateIntrusionSetInput') updateIntrusionSetInput: UpdateIntrusionSetInput,
  ) {
    return this.intrusionSetService.update(id, updateIntrusionSetInput);
  }

  @Mutation(() => Boolean)
  async removeIntrusionSet(@Args('id') id: string) {
    return this.intrusionSetService.remove(id);
  }

  @Query(() => IntrusionSet)
  async searchIntrusionSets(
    @Args('filters', { type: () => SearchIntrusionSetInput, nullable: true }) filters?: Partial<SearchIntrusionSetInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number,
  ) {
    return this.intrusionSetService.searchIntrusionSetWithFilters(filters, page, pageSize);
  }
}
