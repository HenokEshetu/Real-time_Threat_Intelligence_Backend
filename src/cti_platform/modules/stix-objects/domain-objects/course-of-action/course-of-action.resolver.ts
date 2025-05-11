import { Resolver, Query, InputType, Mutation, Args, Int, Subscription, } from '@nestjs/graphql';
import { CourseOfActionService } from './course-of-action.service';
import { CreateCourseOfActionInput, UpdateCourseOfActionInput } from './course-of-action.input';
import { CourseOfAction } from './course-of-action.entity';
import { PartialType } from '@nestjs/graphql';
import { ObjectType, Field } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

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
export class CourseOfActionResolver  {
    constructor(
        private readonly courseOfActionService: CourseOfActionService,
        @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
      ) { }
    
      // Date conversion helper
      public convertDates(payload: any): CourseOfAction {
        const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
        dateFields.forEach(field => {
          if (payload[field]) payload[field] = new Date(payload[field]);
        });
        return payload;
      }
    
      // Subscription Definitions
      @Subscription(() => CourseOfAction, {
        name: 'courseOfActionCreated',
        resolve: (payload) => payload,
      })
      courseOfActionCreated() {
        return this.pubSub.asyncIterator('courseOfActionCreated');
      }
    
      @Subscription(() => CourseOfAction, {
        name: 'courseOfActionUpdated',
        resolve: (payload) => payload,
      })
      courseOfActionUpdated() {
        return this.pubSub.asyncIterator('courseOfActionUpdated');
      }
    
      @Subscription(() => String, { name: 'courseOfActionDeleted' })
      courseOfActionDeleted() {
        return this.pubSub.asyncIterator('courseOfActionDeleted');
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