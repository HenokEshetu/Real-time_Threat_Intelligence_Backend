import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { CreateNoteInput, UpdateNoteInput } from './note.input';
import { v4 as uuidv4 } from 'uuid';
import { SearchNoteInput } from './note.resolver';
import { Note } from './note.entity';

@Injectable()
export class NoteService implements OnModuleInit {
  private readonly index = 'notes';
  private readonly openSearchService: Client;

  constructor() {
    const clientOptions: ClientOptions = {
      node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
      ssl: process.env.OPENSEARCH_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
      auth: process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD
        ? {
            username: process.env.OPENSEARCH_USERNAME,
            password: process.env.OPENSEARCH_PASSWORD,
          }
        : undefined,
    };
    this.openSearchService = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }

  async create(createNoteInput: CreateNoteInput): Promise<Note> {
    const note: Note = {
      id: `note--${uuidv4()}`,
      type: 'note' as const,
      spec_version: '2.1',
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      content: createNoteInput.content, // Required field
      ...createNoteInput,
    };

    try {
      const response = await this.openSearchService.index({
        index: this.index,
        id: note.id,
        body: note,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'created') {
        throw new Error('Failed to index note');
      }
      return note;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create note',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findOne(id: string): Promise<Note> {
    try {
      const response = await this.openSearchService.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        id: response.body._id,
        type: 'note' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        object_refs: source.object_refs,
        abstract:source.abstract,
        content: source.content, // Required field
        ...source,
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Note with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch note',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateNoteInput: UpdateNoteInput): Promise<Note> {
    try {
      const existingNote = await this.findOne(id);
      const updatedNote: Note = {
        ...existingNote,
        ...updateNoteInput,
        modified: new Date().toISOString(),
      };

      const response = await this.openSearchService.update({
        index: this.index,
        id,
        body: { doc: updatedNote },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update note');
      }

      return updatedNote;
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update note',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchService.delete({
        index: this.index,
        id,
        refresh: 'wait_for',
      });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        return false;
      }
      throw new InternalServerErrorException({
        message: 'Failed to delete note',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async searchWithFilters(
    filters: SearchNoteInput = {},
    page: number = 1,
    pageSize: number = 10
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: Note[];
  }> {
    try {
      const from = (page - 1) * pageSize;
      const queryBuilder: { query: any; sort?: any[] } = {
        query: { bool: { must: [], filter: [], should: [] } },
        sort: [{ modified: { order: 'desc' as const } }],
      };

      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          queryBuilder.query.bool.filter.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          queryBuilder.query.bool.filter.push({ term: { [key]: value } });
        } else if (['created', 'modified'].includes(key)) {
          if (typeof value === 'object' && ('gte' in value || 'lte' in value)) {
            queryBuilder.query.bool.filter.push({ range: { [key]: value } });
          } else if (value instanceof Date) {
            queryBuilder.query.bool.filter.push({
              range: { [key]: { gte: value.toISOString(), lte: value.toISOString() } },
            });
          }
        } else if (typeof value === 'string') {
          if (value.includes('*')) {
            queryBuilder.query.bool.must.push({ wildcard: { [key]: value.toLowerCase() } });
          } else if (value.includes('~')) {
            queryBuilder.query.bool.should.push({
              fuzzy: { [key]: { value: value.replace('~', ''), fuzziness: 'AUTO' } },
            });
          } else {
            queryBuilder.query.bool.must.push({ match_phrase: { [key]: value } });
          }
        }
      }

      if (!queryBuilder.query.bool.must.length && !queryBuilder.query.bool.filter.length && !queryBuilder.query.bool.should.length) {
        queryBuilder.query = { match_all: {} };
      } else if (queryBuilder.query.bool.should.length > 0) {
        queryBuilder.query.bool.minimum_should_match = 1;
      }

      const response = await this.openSearchService.search({
        index: this.index,
        from,
        size: pageSize,
        body: queryBuilder,
      });

      const total = typeof response.body.hits.total === 'number'
        ? response.body.hits.total
        : response.body.hits.total?.value ?? 0;

      return {
        page,
        pageSize,
        total,
        totalPages: Math.ceil(total / pageSize),
        results: response.body.hits.hits.map((hit) => ({
          id: hit._id,
          type: 'note' as const,
          spec_version: hit._source.spec_version || '2.1',
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          content: hit._source.content, // Required field
          abstract: hit._source.abstract,
          object_refs: hit._source.object_refs,
          ...hit._source,
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search notes',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.openSearchService.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.openSearchService.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                created: { type: 'date' },
                modified: { type: 'date' },
                content: { type: 'text' },
                abstract: { type: 'text' },
                authors: { type: 'keyword' },
                object_refs: { type: 'keyword' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize notes index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}