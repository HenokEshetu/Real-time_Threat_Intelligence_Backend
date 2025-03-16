import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { CourseOfActionService } from './course-of-action.service';
import { CreateCourseOfActionInput, UpdateCourseOfActionInput } from './course-of-action.input';
import { NotFoundException } from '@nestjs/common';
import { CourseOfAction } from './course-of-action.entity';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchCourseOfActionInput extends PartialType(CreateCourseOfActionInput){}



@Resolver('CourseOfAction')
export class CourseOfActionResolver {
  constructor(private readonly courseOfActionService: CourseOfActionService) {}

  // 📌 Create a new Course of Action
  @Mutation(() => CourseOfAction)
  async createCourseOfAction(
    @Args('createCourseOfActionInput') createCourseOfActionInput: CreateCourseOfActionInput,
  ): Promise<string> {
    const courseOfAction = await this.courseOfActionService.create(createCourseOfActionInput);
    return courseOfAction.id;
  }

  // 📌 Get a Course of Action by ID
  @Query(() => CourseOfAction, { nullable: true })
  async getCourseOfAction(@Args('id') id: string): Promise<any> {
    const courseOfAction = await this.courseOfActionService.findOne(id);
    if (!courseOfAction) {
      throw new NotFoundException(`Course of Action with ID ${id} not found.`);
    }
    return courseOfAction;
  }

  // 📌 Update a Course of Action
  @Mutation(() => CourseOfAction)
  async updateCourseOfAction(
    @Args('id') id: string,
    @Args('updateCourseOfActionInput') updateCourseOfActionInput: UpdateCourseOfActionInput,
  ): Promise<any> {
    return this.courseOfActionService.update(id, updateCourseOfActionInput);
  }

  // 📌 Delete a Course of Action
  @Mutation(() => Boolean)
  async removeCourseOfAction(@Args('id') id: string): Promise<boolean> {
    return this.courseOfActionService.remove(id);
  }

  // 📌 Search Course of Actions with filters
  @Query(() => CourseOfAction)
  async searchCourseOfActions(
    @Args('filters', { type: () => SearchCourseOfActionInput, nullable: true }) filters: Partial<SearchCourseOfActionInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize: number,
  ): Promise<any> {
    return this.courseOfActionService.searchWithFilters(filters, page, pageSize);
  }
}
