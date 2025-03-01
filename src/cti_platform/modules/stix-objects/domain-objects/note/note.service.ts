import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateNoteInput, UpdateNoteInput } from './note.input';
import { v4 as uuidv4 } from 'uuid';
import { SearchNoteInput } from './note.resolver';
@Injectable()
export class NoteService {
  private readonly index = 'notes'; // OpenSearch index name
  private openSearchService: Client;
  constructor() {
    this.openSearchService = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create Note
  async create(createNoteInput: CreateNoteInput): Promise<any> {
    const note = {
      id: `note--${uuidv4()}`,
      type: 'note',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      ...createNoteInput,
    };

    try {
      await this.openSearchService.index({
        index: this.index,
        id: note.id,
        body: note,
        refresh: 'wait_for',
      });

      return note;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to create note: ${error.message}`);
    }
  }

  // Find Note by ID
  async findOne(id: string): Promise<any> {
    try {
      const { body } = await this.openSearchService.get({
        index: this.index,
        id,
      });

      return body._source;
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Note with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Error fetching note: ${error.message}`);
    }
  }

  // Update Note
  async update(id: string, updateNoteInput: UpdateNoteInput): Promise<any> {
    try {
      const existingNote = await this.findOne(id);

      const updatedNote = {
        ...existingNote,
        ...updateNoteInput,
        modified: new Date().toISOString(),
      };

      await this.openSearchService.index({
        index: this.index,
        id,
        body: updatedNote,
        refresh: 'wait_for',
      });

      return updatedNote;
    } catch (error) {
      throw new InternalServerErrorException(`Failed to update note: ${error.message}`);
    }
  }

  // Delete Note
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
        throw new NotFoundException(`Note with ID ${id} not found.`);
      }
      throw new InternalServerErrorException(`Failed to delete note: ${error.message}`);
    }
  }

  // Search Notes with Filters
  async searchNoteWithFilters(filters: SearchNoteInput, page = 1, pageSize = 10): Promise<any> {
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
      throw new InternalServerErrorException(`Error searching notes in OpenSearch: ${error.message}`);
    }
  }
}
