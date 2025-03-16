import { Injectable, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { EmailMessage } from './email-message.entity';
import { CreateEmailMessageInput, UpdateEmailMessageInput } from './email-message.input';
import { SearchEmailMessageInput } from './email-message.resolver';
@Injectable()
export class EmailMessageService {
  private readonly index = 'email-messages'; // OpenSearch index name

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  // Create a new email message
  async create(createEmailMessageInput: CreateEmailMessageInput): Promise<EmailMessage> {
    const id = `email-msg-${Date.now()}`;
    const now = new Date().toISOString();

    const doc: EmailMessage = {
      id,
      type: 'email-message',
      spec_version: '2.1',
      created: now,
      modified: now,
      ...createEmailMessageInput,
    };

    const response = await this.openSearchClient.index({
      index: this.index,
      id,
      body: doc,
    });

    if (response.body.result !== 'created') {
      throw new InternalServerErrorException('Failed to create email message');
    }

    return doc;
  }

  // Update an existing email message
  async update(id: string, updateEmailMessageInput: UpdateEmailMessageInput): Promise<EmailMessage> {
    const now = new Date().toISOString();
    const existingMessage = await this.findOne(id);

    if (!existingMessage) {
      throw new NotFoundException(`EmailMessage with ID ${id} not found`);
    }

    const updatedDoc: EmailMessage = {
      ...existingMessage,
      ...updateEmailMessageInput,
      modified: new Date().toISOString(),

    };

    await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updatedDoc },
    });

    return updatedDoc;
  }

  // Find a single email message by ID
  async findOne(id: string): Promise<EmailMessage> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      return response.body._source as EmailMessage;
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`EmailMessage with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching data from OpenSearch');
    }
  }

  

  async searchWithFilters(
    searchParams: SearchEmailMessageInput, // Filters passed by the user
    from: number = 0,
    size: number = 10
  ): Promise<EmailMessage[]> {
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
      return body.hits.hits.map((hit) => hit._source as EmailMessage);
    } catch (error) {
      throw new InternalServerErrorException('Error fetching email messages from OpenSearch');
    }
  }
  
  // Remove an email message by ID
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`EmailMessage with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting data from OpenSearch');
    }
  }
}
