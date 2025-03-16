import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { CreateFileInput, UpdateFileInput } from './file.input';
import { File } from './file.entity';

import { SearchFileInput } from './file.resolver';
@Injectable()
export class FileService {
  private readonly index = 'files'; // OpenSearch index name
  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new file document
  async create(createFileInput: CreateFileInput): Promise<File> {
    const id = `file-${Date.now()}`;  // Generate a unique ID for the file
    const now = new Date().toISOString();

    const doc: File = {
      id,
      type: 'file',
      spec_version: '2.1',  // Include spec_version here
      created: now,
      modified: now,
      ...createFileInput,  // Include the properties from createFileInput
    };

    try {
      // Index the document in OpenSearch
      const response = await this.openSearchClient.index({
        index: this.index,
        id,
        body: doc,
      });

      // Ensure that the document was successfully created
      if (response.body.result !== 'created') {
        throw new InternalServerErrorException('Failed to create file');
      }

      return doc;  // Return the created document
    } catch (error) {
      throw new InternalServerErrorException('Error creating file in OpenSearch', error.message);
    }
  }

  // Update an existing file document
  async update(id: string, updateFileInput: UpdateFileInput): Promise<File> {
    const now = new Date().toISOString();

    // Fetch the existing file document from OpenSearch
    const existingFile = await this.findOne(id);
    if (!existingFile) {
      throw new NotFoundException(`File with ID ${id} not found`);
    }

    // Prepare the updated document with the new data
    const updatedDoc = {
      ...existingFile,
      ...updateFileInput,
      spec_version: existingFile.spec_version,  // Retain spec_version during update
      modified: new Date().toISOString(),

    };

    try {
      // Update the document in OpenSearch
      await this.openSearchClient.update({
        index: this.index,
        id,
        body: { doc: updatedDoc },
      });

      return updatedDoc;  // Return the updated document
    } catch (error) {
      throw new InternalServerErrorException('Error updating file in OpenSearch', error.message);
    }
  }


  async searchWithFilters(
    searchParams: SearchFileInput , // Filters passed by the user
    from: number = 0,
    size: number = 10
  ): Promise<File[]> {
    try {
      const mustQueries = [];
  
      // Construct dynamic search query based on filters (searchParams)
      for (const [key, value] of Object.entries(searchParams)) {
        if (value !== undefined) {
          if (value instanceof Date) {
            mustQueries.push({
              range: { [key]: { gte: value.toISOString() } }, // Filters based on a date range (greater than or equal to)
            });
          } else {
            mustQueries.push({ match: { [key]: value } });
          }
        }
      }
  
      // Use match_all if no filters are provided
      const query = mustQueries.length > 0 ? { bool: { must: mustQueries } } : { match_all: {} };
  
      // Execute search query in OpenSearch
      const { body } = await this.openSearchClient.search({
        index: this.index,
        from,
        size,
        body: { query },
      });
  
      // Map the results to the required structure
      return body.hits.hits.map((hit) => hit._source as File);
    } catch (error) {
      throw new InternalServerErrorException('Error fetching email messages from OpenSearch');
    }
  }



  // Find a file by its ID
  async findOne(id: string): Promise<File | null> {
    try {
      const response = await this.openSearchClient.get({
        index: this.index,
        id,
      });

      // Return the document source (the actual file data)
      return {
        id,
        type: 'file',
        spec_version: response.body._source.spec_version || '2.1',  // Ensure spec_version is included
        created: response.body._source.created || new Date().toISOString(),
        modified: response.body._source.modified || new Date().toISOString(),
        ...response.body._source,
      };
    } catch (error) {
      if (error.meta?.body?.found === false) {
        return null;  // Return null if the file was not found
      }
      throw new InternalServerErrorException('Error fetching file from OpenSearch', error.message);
    }
  }

  // Remove a file document by its ID
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });

      return response.body.result === 'deleted';  // Return true if the document was deleted
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`File with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting file in OpenSearch', error.message);
    }
  }

  // Find files by hash (for example, by sha256)
  async findByHash(hashValue: string): Promise<File[]> {
    try {
      const response = await this.openSearchClient.search({
        index: this.index,
        body: {
          query: {
            bool: {
              should: [
                {
                  match: {
                    'hashes.sha_256': hashValue,  // Search by the sha256 hash field
                  },
                },
                // You can add other hash types here (e.g., md5, sha1)
                {
                  match: {
                    'hashes.md5': hashValue,  // Optional, search by md5 hash
                  },
                },
              ],
            },
          },
        },
      });

      // Return the matched documents
      return response.body.hits.hits.map((hit) => ({
        id: hit._id,
        type: 'file',
        spec_version: hit._source.spec_version || '2.1',
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        hashes: hit._source.hashes,  // Ensure hashes field is included
        ...hit._source,
      }));
    } catch (error) {
      throw new InternalServerErrorException('Error fetching files by hash from OpenSearch', error.message);
    }
  }




}
