import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { EmailAddress } from './email-address.entity';
import { CreateEmailAddressInput, UpdateEmailAddressInput } from './email-address.input';
import { SearchEmailAddressInput } from './email-address.resolver';
@Injectable()
export class EmailAddressService {
  private readonly index = 'email-addresses';

  private openSearchClient: Client;
  constructor() {
    this.openSearchClient = new Client({
      node: 'http://localhost:9200',
    });
  }

  async create(createEmailAddressInput: CreateEmailAddressInput): Promise<EmailAddress> {
    const id = `email-${Date.now()}`;
    const now = new Date().toISOString();

    const doc: EmailAddress = {
      id,
      type: 'email-addr',
      spec_version: '2.1',
      created: now,
      modified: now,
      value: createEmailAddressInput.value,
      display_name: createEmailAddressInput.display_name || '',
      ...createEmailAddressInput,
    };

    const response = await this.openSearchClient.index({
      index: this.index,
      id,
      body: doc,
    });

    if (response.body.result !== 'created') {
      throw new InternalServerErrorException('Failed to create email address');
    }

    return doc;
  }

  async update(id: string, updateEmailAddressInput: UpdateEmailAddressInput): Promise<EmailAddress> {
    const now = new Date().toISOString();
    const existingEmail = await this.findOne(id);

    if (!existingEmail) {
      throw new NotFoundException(`EmailAddress with ID ${id} not found`);
    }

    const updatedDoc: EmailAddress = {
      ...existingEmail,
      ...updateEmailAddressInput,
      modified: new Date().toISOString(),

    };

    await this.openSearchClient.update({
      index: this.index,
      id,
      body: { doc: updatedDoc },
    });

    return updatedDoc;
  }

  async findOne(id: string): Promise<EmailAddress> {
    try {
      const response = await this.openSearchClient.get({ index: this.index, id });
      return response.body._source as EmailAddress; 
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`EmailAddress with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error fetching data from OpenSearch');
    }
  }

  async findByValue(value: string): Promise<EmailAddress[]> {
    const response = await this.openSearchClient.search({
      index: this.index,
      body: { query: { term: { value } } }, // Using 'term' for exact match
    });

    return response.body.hits.hits.map((hit) => hit._source as EmailAddress);
  }

  async findByDisplayName(displayName: string): Promise<EmailAddress[]> {
    const response = await this.openSearchClient.search({
      index: this.index,
      body: { query: { term: { display_name: displayName } } }, // Using 'term' for exact match
    });

    return response.body.hits.hits.map((hit) => hit._source as EmailAddress);
  }

  async searchWithFilters(
    searchParams:  SearchEmailAddressInput, // Filters passed by the user
    from: number = 0,
    size: number = 10
  ): Promise<EmailAddress[]> {
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
      return body.hits.hits.map((hit) => hit._source as EmailAddress);
    } catch (error) {
      throw new InternalServerErrorException('Error fetching email addresses from OpenSearch');
    }
  }
  
  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.openSearchClient.delete({
        index: this.index,
        id,
      });
      return response.body.result === 'deleted';
    } catch (error) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`EmailAddress with ID ${id} not found`);
      }
      throw new InternalServerErrorException('Error deleting data from OpenSearch');
    }
  }
}
