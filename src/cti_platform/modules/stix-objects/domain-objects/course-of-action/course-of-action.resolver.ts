import { Resolver, Query, InputType, Mutation, Args, Int, } from '@nestjs/graphql';
import { CourseOfActionService } from './course-of-action.service';
import { CreateCourseOfActionInput, UpdateCourseOfActionInput } from './course-of-action.input';
import { CourseOfAction } from './course-of-action.entity';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

@InputType()
export class SearchCourseOfActionInput extends PartialType(CreateCourseOfActionInput){}

@ObjectType()
export class CourseOfActionSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [CourseOfAction])
  results: CourseOfAction[];
}

@Resolver(() => CourseOfAction)
export class CourseOfActionResolver extends BaseStixResolver(CourseOfAction) {
  public typeName = 'course-of-action';
  constructor(private readonly courseOfActionService: CourseOfActionService) {
    super()
  }

  @Mutation(() => CourseOfAction)
  async createCourseOfAction(
    @Args('input') createCourseOfActionInput: CreateCourseOfActionInput,
  ): Promise<CourseOfAction> {
    return this.courseOfActionService.create(createCourseOfActionInput);
  }

  @Query(() => CourseOfActionSearchResult)
  async searchCoursesOfAction(
    @Args('filters', { type: () => SearchCourseOfActionInput, nullable: true }) filters: SearchCourseOfActionInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<CourseOfActionSearchResult> {
    return this.courseOfActionService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => CourseOfAction, { nullable: true })
  async courseOfAction(@Args('id') id: string): Promise<CourseOfAction> {
    return this.courseOfActionService.findOne(id);
  }

  @Mutation(() => CourseOfAction)
  async updateCourseOfAction(
    @Args('id') id: string,
    @Args('input') updateCourseOfActionInput: UpdateCourseOfActionInput,
  ): Promise<CourseOfAction> {
    return this.courseOfActionService.update(id, updateCourseOfActionInput);
  }

  @Mutation(() => Boolean)
  async deleteCourseOfAction(@Args('id') id: string): Promise<boolean> {
    return this.courseOfActionService.remove(id);
  }
}