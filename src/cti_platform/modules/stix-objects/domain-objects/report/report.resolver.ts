import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { ReportService } from './report.service';
import { CreateReportInput, UpdateReportInput } from './report.input';
import { Report } from './report.entity';
import { ObjectType, Field } from '@nestjs/graphql';

import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

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
export class ReportResolver extends BaseStixResolver(Report) {
  public typeName = 'indicator';
  
  constructor(private readonly reportService: ReportService) {
    super()
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