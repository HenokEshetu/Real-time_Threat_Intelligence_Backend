import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { ReportService } from './report.service';
import { CreateReportInput, UpdateReportInput } from './report.input';
import { NotFoundException } from '@nestjs/common';
import { Report } from './report.entity';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchReportInput extends PartialType(CreateReportInput){}


@Resolver('Report')
export class ReportResolver {
  constructor(private readonly reportService: ReportService) {}

  // Create a new report
  @Mutation(() => Report)
  async createReport(@Args('createReportInput') createReportInput: CreateReportInput) {
    return this.reportService.create(createReportInput);
  }

  // Get a single report by ID
  @Query(() => Report, { nullable: true })
  async getReport(@Args('id') id: string) {
    const report = await this.reportService.findOne(id);
    if (!report) throw new NotFoundException(`Report with ID ${id} not found.`);
    return report;
  }

  //  Update a report
  @Mutation(() => Report)
  async updateReport(
    @Args('id') id: string,
    @Args('updateReportInput') updateReportInput: UpdateReportInput,
  ) {
    return this.reportService.update(id, updateReportInput);
  }

  // Delete a report
  @Mutation(() => Boolean)
  async removeReport(@Args('id') id: string) {
    return this.reportService.remove(id);
  }

  // Search reports with dynamic filters
  @Query(() => Report)
  async searchReports(
    @Args('filters', { type: () => SearchReportInput, nullable: true }) filters?: Partial<SearchReportInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number,
  ) {
    return this.reportService.searchReportWithFilters(filters, page, pageSize);
  }
}
