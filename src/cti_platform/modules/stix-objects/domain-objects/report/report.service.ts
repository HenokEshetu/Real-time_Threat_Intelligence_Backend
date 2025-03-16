import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { v4 as uuidv4 } from 'uuid';
import { CreateReportInput, UpdateReportInput } from './report.input';
import { SearchReportInput } from './report.resolver';
@Injectable()
export class ReportService {
  private readonly index = 'reports'; // OpenSearch index name

  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  //  Create a new report
  async create(createReportInput: CreateReportInput): Promise<any> {
    const report = {
      id: `report--${uuidv4()}`,
      type: 'report',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createReportInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: report.id,
        body: report,
        refresh: 'wait_for',
      });

      return report;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create report: ${error.message}`);
    }
  }

  // Get a single report by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Report with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching report: ${error.message}`);
    }
  }

  //  Update a report
  async update(id: string, updateReportInput: UpdateReportInput): Promise<any> {
    try {
      const existingReport = await this.findOne(id);

      const updatedReport = {
        ...existingReport,
        ...updateReportInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedReport,
        refresh: 'wait_for',
      });

      return updatedReport;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update report: ${error.message}`);
    }
  }

  //  Delete a report
  async remove(id: string): Promise<boolean> {
    try {
      const { body } = await this.openSearchService.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });

      return body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Report with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete report: ${error.message}`);
    }
  }

  // Search reports with dynamic filters
  async searchReportWithFilters(filters: SearchReportInput, page = 1, pageSize = 10): Promise<any> {
    try {
      const from = (page - 1) * pageSize;
      const mustQueries = [];
      const shouldQueries = [];
      const filterQueries = [];

      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          mustQueries.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          mustQueries.push({ term: { [key]: value } });
        } else if (['created', 'modified'].includes(key)) {
          if (typeof value === 'object' && ('gte' in value || 'lte' in value)) {
            filterQueries.push({ range: { [key]: value } });
          } else {
            filterQueries.push({ range: { [key]: { gte: value } } });
          }
        } else if (typeof value === 'string') {
          if (value.includes('*')) {
            mustQueries.push({ wildcard: { [key]: value.toLowerCase() } });
          } else if (value.includes('~')) {
            shouldQueries.push({ fuzzy: { [key]: { value, fuzziness: 'AUTO' } } });
          } else {
            mustQueries.push({ match_phrase: { [key]: value } });
          }
        }
      }

      const query: any = { bool: {} };
      if (mustQueries.length > 0) query.bool.must = mustQueries;
      if (shouldQueries.length > 0) query.bool.should = shouldQueries;
      if (filterQueries.length > 0) query.bool.filter = filterQueries;
      if (Object.keys(query.bool).length === 0) query.bool.must = [{ match_all: {} }];

      const { body } = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: {
          query,
          sort: [{ created: { order: 'desc' } }],
        },
      });

      const total = typeof body.hits.total === 'number' ? body.hits.total : body.hits.total?.value ?? 0;

      return {
        total,
        page,
        pageSize,
        results: body.hits.hits.map((hit) => ({
          id: hit._id,
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException(`Error searching reports in OpenSearch: ${error.message}`);
    }
  }
}
