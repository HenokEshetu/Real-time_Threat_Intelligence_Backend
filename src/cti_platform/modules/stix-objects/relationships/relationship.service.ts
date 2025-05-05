import { Injectable, InternalServerErrorException, NotFoundException, OnModuleInit } from '@nestjs/common';
import { Client, ClientOptions } from '@opensearch-project/opensearch';
import { StixRelationship } from './relationship.entity';
import { CreateRelationshipInput, UpdateRelationshipInput } from './relationship.input';
import { StixValidationError } from '../../../core/exception/custom-exceptions';
import { SearchRelationshipInput } from './relationship.resolver';

import { v5 as uuidv5 } from 'uuid';

// Define the UUID namespace (DNS namespace in this example)
const NAMESPACE = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';

@Injectable()
export class RelationshipService implements OnModuleInit {
  private readonly client: Client;
  private readonly index = 'stix-relationships';

  
  private readonly validRelationships = new Map<string, Set<string>>([
    ['attack-pattern', new Set(['delivers', 'targets', 'uses'])],
    ['campaign', new Set(['attributed-to', 'compromises', 'originates-from', 'targets', 'uses'])],
    ['course-of-action', new Set(['investigates', 'mitigates'])],
    ['identity', new Set(['located-at'])],
    ['indicator', new Set(['indicates', 'based-on'])],
    ['infrastructure', new Set(['communicates-with', 'consists-of', 'controls', 'delivers', 'has', 'hosts', 'located-at', 'uses'])],
    ['intrusion-set', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'originates-from', 'targets', 'uses'])],
    ['malware', new Set(['authored-by', 'beacons-to', 'exfiltrate-to', 'communicates-with', 'controls', 'downloads', 'drops', 'exploits', 'originates-from', 'targets', 'uses', 'variant-of'])],
    ['malware-analysis', new Set(['characterizes', 'analysis-of', 'static-analysis-of', 'dynamic-analysis-of'])],
    ['threat-actor', new Set(['attributed-to', 'compromises', 'hosts', 'owns', 'impersonates', 'located-at', 'targets', 'uses'])],
    ['tool', new Set(['delivers', 'drops', 'has', 'targets'])],
  ]);
  
  private readonly validTargets = new Map<string, Set<string>>([
    ['delivers', new Set(['malware'])],
    ['targets', new Set(['identity', 'location', 'vulnerability', 'infrastructure'])],
    ['uses', new Set(['attack-pattern', 'infrastructure', 'malware', 'tool'])],
    ['attributed-to', new Set(['intrusion-set', 'threat-actor', 'identity'])],
    ['compromises', new Set(['infrastructure'])],
    ['originates-from', new Set(['location'])],
    ['investigates', new Set(['indicator'])],
    ['mitigates', new Set(['attack-pattern', 'indicator', 'malware', 'tool', 'vulnerability'])],
    ['located-at', new Set(['location'])],
    ['indicates', new Set(['attack-pattern', 'campaign', 'infrastructure', 'intrusion-set', 'malware', 'threat-actor', 'tool'])],
    ['based-on', new Set([
      'observed-data',
      'ipv4-addr',
      'ipv6-addr',
      'domain-name',
      'url',
      'email-addr',
      'file',
      'mutex',
      'windows-registry-key',
      'x509-certificate',
      'autonomous-system',
      'network-traffic',
      'software',
      'user-account',
      'mac-addr',
      'process',
      'directory',
      'artifact'
    ])],
    ['communicates-with', new Set(['infrastructure'])],
    ['consists-of', new Set(['infrastructure'])],
    ['controls', new Set(['infrastructure', 'malware'])],
    ['has', new Set(['vulnerability'])],
    ['hosts', new Set(['infrastructure', 'malware'])],
    ['authored-by', new Set(['threat-actor'])],
    ['beacons-to', new Set(['infrastructure'])],
    ['exfiltrate-to', new Set(['infrastructure'])],
    ['downloads', new Set(['malware', 'tool'])],
    ['drops', new Set(['malware', 'tool'])],
    ['exploits', new Set(['vulnerability'])],
    ['variant-of', new Set(['malware'])],
    ['characterizes', new Set(['malware'])],
    ['analysis-of', new Set(['malware'])],
    ['static-analysis-of', new Set(['malware'])],
    ['dynamic-analysis-of', new Set(['malware'])],
    ['owns', new Set(['infrastructure'])],
    ['impersonates', new Set(['identity'])],
  ]);
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
    this.client = new Client(clientOptions);
  }

  async onModuleInit() {
    await this.ensureIndex();
  }


  async create(createRelationshipInput: CreateRelationshipInput): Promise<StixRelationship> {
    try {
      // Validate relationship first
      this.validateRelationship(
        createRelationshipInput.source_ref,
        createRelationshipInput.relationship_type,
        createRelationshipInput.target_ref
      );

      // Generate deterministic ID based on relationship properties
      const idSeed = [
        createRelationshipInput.source_ref,
        createRelationshipInput.relationship_type,
        createRelationshipInput.target_ref,
        createRelationshipInput.start_time || '',
        createRelationshipInput.stop_time || '',
        Date.now().toString() // Ensure uniqueness for concurrent requests
      ].join('|');

      const relationship: StixRelationship = {
        ...createRelationshipInput,
        id: createRelationshipInput.id || `relationship--${uuidv5(idSeed, NAMESPACE)}`,
        type: 'relationship',
        spec_version: '2.1',
        start_time: createRelationshipInput.start_time 
          ? new Date(createRelationshipInput.start_time).toISOString() 
          : undefined,
        stop_time: createRelationshipInput.stop_time 
          ? new Date(createRelationshipInput.stop_time).toISOString() 
          : undefined,
        created: new Date().toISOString(),
        modified: new Date().toISOString(),
      };

      const response = await this.client.index({
        index: this.index,
        id: relationship.id,
        body: relationship,
        refresh: 'wait_for',
      }).catch(error => {
        throw new Error(`OpenSearch error: ${this.safeGetErrorMessage(error)}`);
      });

      if (!['created', 'updated'].includes(response.body?.result)) {
        throw new Error(`Unexpected OpenSearch response: ${JSON.stringify(response.body)}`);
      }

      return relationship;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to create relationship',
        details: this.safeGetErrorMessage(error),
        objectId: createRelationshipInput?.id || 'unknown',
        input: createRelationshipInput
      });
    }
  }

  private safeGetErrorMessage(error: any): string {
    if (typeof error === 'string') return error;
    if (error?.message) return error.message;
    if (error?.response?.data?.error) return error.response.data.error;
    if (error?.body?.error) return JSON.stringify(error.body.error);
    return 'Unknown error occurred';
  }

  async findOne(id: string): Promise<StixRelationship> {
    try {
      const response = await this.client.get({
        index: this.index,
        id,
      });

      const source = response.body._source;
      return {
        ...source,
        id: response.body._id,
        type: 'relationship' as const,
        spec_version: source.spec_version || '2.1',
        created: source.created || new Date().toISOString(),
        modified: source.modified || new Date().toISOString(),
        source_ref: source.source_ref,
        target_ref: source.target_ref,
        relationship_type: source.relationship_type,
        
      };
    } catch (error) {
      if (error.meta?.statusCode === 404) {
        throw new NotFoundException(`Relationship with ID ${id} not found`);
      }
      throw new InternalServerErrorException({
        message: 'Failed to fetch relationship',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async update(id: string, updateRelationshipInput: UpdateRelationshipInput): Promise<StixRelationship> {
    try {
      if (updateRelationshipInput.source_ref && updateRelationshipInput.relationship_type && updateRelationshipInput.target_ref) {
        this.validateRelationship(
          updateRelationshipInput.source_ref,
          updateRelationshipInput.relationship_type,
          updateRelationshipInput.target_ref
        );
      }

      const existingRelationship = await this.findOne(id);
      const updatedFields = {
        ...updateRelationshipInput,
        start_time: updateRelationshipInput.start_time ? new Date(updateRelationshipInput.start_time).toISOString() : existingRelationship.start_time,
        stop_time: updateRelationshipInput.stop_time ? new Date(updateRelationshipInput.stop_time).toISOString() : existingRelationship.stop_time,
        modified: new Date().toISOString(),
      };

      const response = await this.client.update({
        index: this.index,
        id,
        body: { doc: updatedFields },
        retry_on_conflict: 3,
        refresh: 'wait_for',
      });

      if (response.body.result !== 'updated') {
        throw new Error('Failed to update relationship');
      }

      return await this.findOne(id);
    } catch (error) {
      if (error instanceof NotFoundException) throw error;
      throw new InternalServerErrorException({
        message: 'Failed to update relationship',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async remove(id: string): Promise<boolean> {
    try {
      const response = await this.client.delete({
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
        message: 'Failed to delete relationship',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async ensureIndex(): Promise<void> {
    try {
      const exists = await this.client.indices.exists({ index: this.index });
      if (!exists.body) {
        await this.client.indices.create({
          index: this.index,
          body: {
            mappings: {
              properties: {
                id: { type: 'keyword' },
                type: { type: 'keyword' },
                spec_version: { type: 'keyword' },
                source_ref: { type: 'keyword' },
                target_ref: { type: 'keyword' },
                relationship_type: { type: 'keyword' },
                description: { type: 'text' },
                created: { type: 'date' },
                modified: { type: 'date' },
                start_time: { type: 'date' },
                stop_time: { type: 'date' },
              },
            },
          },
        });
      }
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to initialize relationships index',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  private validateRelationship(sourceRef: string, relationshipType: string, targetRef: string): void {
    const sourceType = sourceRef.split('--')[0];
    const targetType = targetRef.split('--')[0];

    const validRelationshipsForSource = this.validRelationships.get(sourceType);
    if (!validRelationshipsForSource?.has(relationshipType)) {
      throw new StixValidationError(
        `Invalid relationship: ${sourceType} cannot have relationship type '${relationshipType}'`
      );
    }

    const validTargetTypes = this.validTargets.get(relationshipType);
    if (validTargetTypes && !validTargetTypes.has(targetType)) {
      throw new StixValidationError(
        `Invalid relationship target: ${relationshipType} relationship cannot target ${targetType}`
      );
    }
  }

  async searchWithFilters(
    filters: SearchRelationshipInput = {},
    page: number = 1,
    pageSize: number = 10,
    sortField: keyof StixRelationship = 'modified',
    sortOrder: 'asc' | 'desc' = 'desc'
  ): Promise<{
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
    results: StixRelationship[];
  }> {
    try {
      const from = Math.max(0, (page - 1) * pageSize); // Ensure from is non-negative
      const queryBuilder: { query: any; sort: any[] } = {
        query: { bool: { must: [], filter: [], should: [] } },
        sort: [{ [sortField]: { order: sortOrder } }],
      };

      for (const [key, value] of Object.entries(filters)) {
        if (!value) continue;

        if (Array.isArray(value)) {
          queryBuilder.query.bool.filter.push({ terms: { [key]: value } });
        } else if (typeof value === 'boolean' || typeof value === 'number') {
          queryBuilder.query.bool.filter.push({ term: { [key]: value } });
        } else if (['start_time', 'stop_time', 'created', 'modified'].includes(key)) {
          if (typeof value === 'object' && ('gte' in value || 'lte' in value || 'gt' in value || 'lt' in value)) {
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

      const response = await this.client.search({
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
          ...hit._source,
          id: hit._id,
          type: 'relationship' as const,
          spec_version: hit._source.spec_version || '2.1',
          source_ref: hit._source.source_ref,
          target_ref: hit._source.target_ref,
          relationship_type: hit._source.relationship_type,
          created: hit._source.created || new Date().toISOString(),
          modified: hit._source.modified || new Date().toISOString(),
          start_time: hit._source.start_time,
          stop_time: hit._source.stop_time,
         
        })),
      };
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to search relationships',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findRelatedObjects(objectId: string): Promise<StixRelationship[]> {
    try {
      const response = await this.client.search({
        index: this.index,
        body: {
          query: {
            bool: {
              should: [
                { term: { source_ref: objectId } },
                { term: { target_ref: objectId } },
              ],
              minimum_should_match: 1,
            },
          },
        },
      });

      return response.body.hits.hits.map((hit) => ({
        ...hit._source,
        id: hit._id,
        type: 'relationship' as const,
        spec_version: hit._source.spec_version || '2.1',
        source_ref: hit._source.source_ref,
        target_ref: hit._source.target_ref,
        relationship_type: hit._source.relationship_type,
        created: hit._source.created || new Date().toISOString(),
        modified: hit._source.modified || new Date().toISOString(),
        start_time: hit._source.start_time,
        stop_time: hit._source.stop_time,
        
      }));
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to fetch related objects',
        details: error.meta?.body?.error || error.message,
      });
    }
  }

  async findExpandedRelatedObjects(objectId: string): Promise<any[]> {
    try {
      // Fetch relationships
      const relationships = await this.findRelatedObjects(objectId);
      if (!relationships.length) return [];

      // Collect unique related object IDs
      const relatedObjectIds = new Set<string>();
      relationships.forEach((rel) => {
        relatedObjectIds.add(rel.source_ref);
        relatedObjectIds.add(rel.target_ref);
      });
      relatedObjectIds.delete(objectId);

      if (relatedObjectIds.size === 0) return [];

      const relatedIdsArray = Array.from(relatedObjectIds);
      const chunkSize = 1000; // Configurable based on OpenSearch limits
      const results: any[] = [];

      // Process in batches
      for (let i = 0; i < relatedIdsArray.length; i += chunkSize) {
        const chunk = relatedIdsArray.slice(i, i + chunkSize);

        const response = await this.client.search({
          index: 'stix-objects',
          body: {
            query: {
              terms: { id: chunk },
            },
            // Only fetch necessary fields to reduce payload
            _source: ['id', 'type', 'name', 'created', 'modified'],
          },
        });

        const chunkResults = response.body.hits.hits.map((hit) => ({
          ...hit._source,
          id: hit._id,
          
        }));

        results.push(...chunkResults);
      }

      return results;
    } catch (error) {
      throw new InternalServerErrorException({
        message: 'Failed to fetch expanded related objects',
        details: error.meta?.body?.error || error.message,
      });
    }
  }
}