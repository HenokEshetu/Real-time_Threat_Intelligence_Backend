import { Resolver, Query, Mutation, Args, Int, InputType, ObjectType, Field, PartialType } from '@nestjs/graphql';
import { v4 as uuidv4 } from 'uuid';
import { ExternalReference } from 'src/cti_platform/core/types/common-data-types'; // <-- Import the shared type

// --- Mock Data Types ---
@ObjectType()
export class Report {
  @Field() id: string;
  @Field() name: string;
  @Field({ nullable: true }) description?: string;
  @Field(() => [String], { nullable: true }) authors?: string[];
  @Field({ nullable: true }) published?: string;
  @Field(() => [String], { nullable: true }) report_types?: string[];
  @Field({ nullable: true }) confidence?: number;
  @Field({ nullable: true }) created?: string;
  @Field({ nullable: true }) modified?: string;
  @Field(() => [String], { nullable: true }) labels?: string[];
  @Field(() => [String], { nullable: true }) object_refs?: string[];
  @Field(() => [ExternalReference], { nullable: true }) external_references?: ExternalReference[];
}

@InputType()
export class CreateReportInput {
  @Field() name: string;
  @Field({ nullable: true }) description?: string;
  @Field(() => [String], { nullable: true }) authors?: string[];
  @Field({ nullable: true }) published?: string;
  @Field(() => [String], { nullable: true }) report_types?: string[];
  @Field({ nullable: true }) confidence?: number;
  @Field(() => [String], { nullable: true }) labels?: string[];
}

@InputType()
export class UpdateReportInput extends PartialType(CreateReportInput) {}

@InputType()
export class SearchReportInput extends PartialType(CreateReportInput) {}

@ObjectType()
export class ReportSearchResult {
  @Field(() => Int) page: number;
  @Field(() => Int) pageSize: number;
  @Field(() => Int) total: number;
  @Field(() => Int) totalPages: number;
  @Field(() => [Report]) results: Report[];
}

// --- Mock Data Store ---
const mockReports: Report[] = [
  {
    id: '1',
    name: 'APT29 Activity Report',
    description: 'Analysis of APT29 operations in 2023.',
    authors: ['Alice', 'Bob'],
    published: '2023-11-01',
    report_types: ['threat-report', 'campaign'],
    confidence: 85,
    created: '2023-10-25T12:00:00Z',
    modified: '2023-11-01T09:00:00Z',
    labels: ['APT29', 'Russia', 'Espionage'],
    object_refs: [],
    external_references: [
      { id: 'ref-1', source_name: 'mitre-attack', url: 'https://attack.mitre.org/groups/G0016/', external_id: 'G0016' }
    ]
  },
  {
    id: '2',
    name: 'Ransomware Trends Q4',
    description: 'Quarterly ransomware trends and statistics.',
    authors: ['Charlie'],
    published: '2023-12-15',
    report_types: ['threat-report'],
    confidence: 70,
    created: '2023-12-01T08:00:00Z',
    modified: '2023-12-15T10:00:00Z',
    labels: ['ransomware', 'statistics'],
    object_refs: [],
    external_references: []
  }
];

// --- Resolver ---
@Resolver(() => Report)
export class ReportResolver {
  // --- CREATE ---
  @Mutation(() => Report)
  async createReport(
    @Args('input') input: CreateReportInput,
  ): Promise<Report> {
    const newReport: Report = {
      id: uuidv4(),
      ...input,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      external_references: [],
      object_refs: [],
    };
    mockReports.push(newReport);
    return newReport;
  }

  // --- SEARCH (paginated, but frontend expects array or paginated object) ---
  @Query(() => [Report])
  async searchReports(
    @Args('filters', { type: () => SearchReportInput, nullable: true }) filters: SearchReportInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number = 1,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number = 10,
  ): Promise<Report[]> {
    // Simple filter by name
    let results = mockReports;
    if (filters?.name) {
      results = results.filter(r => r.name.toLowerCase().includes(filters.name.toLowerCase()));
    }
    // Pagination
    const start = (page - 1) * pageSize;
    return results.slice(start, start + pageSize);
  }

  // --- GET BY ID ---
  @Query(() => Report, { nullable: true })
  async getReport(@Args('id') id: string): Promise<Report | undefined> {
    return mockReports.find(r => r.id === id);
  }

  // --- UPDATE ---
  @Mutation(() => Report)
  async updateReport(
    @Args('id') id: string,
    @Args('input') input: UpdateReportInput,
  ): Promise<Report> {
    const idx = mockReports.findIndex(r => r.id === id);
    if (idx === -1) throw new Error('Report not found');
    mockReports[idx] = {
      ...mockReports[idx],
      ...input,
      modified: new Date().toISOString(),
    };
    return mockReports[idx];
  }

  // --- DELETE ---
  @Mutation(() => Boolean)
  async deleteReport(@Args('id') id: string): Promise<boolean> {
    const idx = mockReports.findIndex(r => r.id === id);
    if (idx === -1) return false;
    mockReports.splice(idx, 1);
    return true;
  }
}
