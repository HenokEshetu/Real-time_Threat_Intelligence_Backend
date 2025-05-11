import { Resolver, Query,InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { ReportService } from './report.service';
import { CreateReportInput, UpdateReportInput } from './report.input';
import { Report } from './report.entity';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchReportInput extends PartialType(CreateReportInput){}

@ObjectType()
export class ReportSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Report])
  results: Report[];
}

@Resolver(() => Report)
export class ReportResolver {
    constructor(
      private readonly reportService: ReportService,
      @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
    ) { }
  
    // Date conversion helper
    public convertDates(payload: any): Report {
      const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
      dateFields.forEach(field => {
        if (payload[field]) payload[field] = new Date(payload[field]);
      });
      return payload;
    }
  
    // Subscription Definitions
    @Subscription(() => Report, {
      name: 'reportCreated',
      resolve: (payload) => payload,
    })
    reportCreated() {
      return this.pubSub.asyncIterator('reportCreated');
    }
  
    @Subscription(() => Report, {
      name: 'reportUpdated',
      resolve: (payload) => payload,
    })
    reportUpdated() {
      return this.pubSub.asyncIterator('reportUpdated');
    }
  
    @Subscription(() => String, { name: 'reportDeleted' })
    reportDeleted() {
      return this.pubSub.asyncIterator('reportDeleted');
    }
  
  

  @Mutation(() => Report)
  async createReport(
    @Args('input') createReportInput: CreateReportInput,
  ): Promise<Report> {
    return this.reportService.create(createReportInput);
  }

  @Query(() => ReportSearchResult)
  async searchReports(
    @Args('filters', { type: () => SearchReportInput, nullable: true }) filters: SearchReportInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<ReportSearchResult> {
    return this.reportService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Report, { nullable: true })
  async report(@Args('id') id: string): Promise<Report> {
    return this.reportService.findOne(id);
  }

  @Mutation(() => Report)
  async updateReport(
    @Args('id') id: string,
    @Args('input') updateReportInput: UpdateReportInput,
  ): Promise<Report> {
    return this.reportService.update(id, updateReportInput);
  }

  @Mutation(() => Boolean)
  async deleteReport(@Args('id') id: string): Promise<boolean> {
    return this.reportService.remove(id);
  }
}