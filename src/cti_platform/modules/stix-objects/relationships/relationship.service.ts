import { Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';
import { StixRelationship } from './relationship.entity';
import { CreateRelationshipInput, UpdateRelationshipInput } from './relationship.input';
import { StixValidationError } from '../../../core/exception/custom-exceptions';
import { v4 as uuidv4 } from 'uuid';
import { SearchRelationshipInput } from './relationship.resolver';
@Injectable()
export class RelationshipService {
  private client: Client;
  private readonly index = 'stix-relationships';

  private readonly validRelationships = new Map([
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
    ['tool', new Set(['delivers', 'drops', 'has', 'targets'])]
  ]);

  
  constructor() {
    this.client = new Client({
      node: 'http://localhost:9200',
    });
  }

  /**
   * Create a new StixRelationship
   */
  async create(createRelationshipInput: CreateRelationshipInput): Promise<StixRelationship> {
    this.validateRelationship(
      createRelationshipInput.source_ref,
      createRelationshipInput.relationship_type,
      createRelationshipInput.target_ref
    );
  

const id = `relationship--${uuidv4()}`;
const relationship: StixRelationship = {
  id,
  ...createRelationshipInput,
  start_time: createRelationshipInput.start_time ? new Date().toISOString() : undefined,
  stop_time: createRelationshipInput.stop_time ? new Date().toISOString() : undefined,
  created: new Date().toISOString(),
  modified: new Date().toISOString(),
};

    
    
  
    try {
      await this.client.index({
        index: this.index,
        id,
        body: relationship,
      });
  
      return relationship;
    } catch (error) {
      throw new InternalServerErrorException('Error creating relationship in OpenSearch');
    }
  }
 

  async findOne(id: string): Promise<StixRelationship> {
    try {
      const { body } = await this.client.get({ index: this.index, id });
      return body._source as StixRelationship; // Type assertion
    } catch (error: any) {
      if (error.meta?.body?.found === false) {
        throw new NotFoundException(`Relationship with ID ${id} not found`);
      }
      throw new InternalServerErrorException(`Error retrieving relationship: ${error.message}`);
    }
  }
  
  
  async searchWithFilters(filters: SearchRelationshipInput, page = 1, pageSize = 10): Promise<any> {
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
        } else if (['start_time', 'stop_time', 'created', 'modified'].includes(key)) {
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
  
      if (Object.keys(query.bool).length === 0) {
        query.bool.must = [{ match_all: {} }];
      }
  
      const { body } = await this.client.search({
        index: this.index,
        from,
        size: pageSize,
        body: {
          query,
          sort: [{ created: { order: 'desc' } }],
        },
      });
  
      // ✅ Fix: Safely extract `total`
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
      throw new InternalServerErrorException(`Error searching relationships in OpenSearch: ${error.message}`);
    }
  }
  
  
  async update(id: string, updateRelationshipInput: UpdateRelationshipInput): Promise<StixRelationship> {
    try {
      const updatedFields = {
        ...updateRelationshipInput,
        start_time: updateRelationshipInput.start_time ? new Date(updateRelationshipInput.start_time).toISOString() : undefined,
        stop_time: updateRelationshipInput.stop_time ? new Date(updateRelationshipInput.stop_time).toISOString() : undefined,
        modified: new Date().toISOString(),
      };
  
      await this.client.update({
        index: this.index,
        id,
        body: { doc: updatedFields },
      });
  
      return this.findOne(id);
    } catch (error) {
      throw new InternalServerErrorException('Error updating relationship in OpenSearch');
    }
  }
  
  /**
   * Delete a relationship
   */
  async remove(id: string): Promise<boolean> {
    try {
      const { body } = await this.client.delete({ index: this.index, id });
      return body.result === 'deleted';
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate STIX relationship
   */
  private validateRelationship(sourceRef: string, relationshipType: string, targetRef: string): void {
    const sourceType = sourceRef.split('--')[0];
    const targetType = targetRef.split('--')[0];

    const validRelationshipsForSource = this.validRelationships.get(sourceType);

    if (!validRelationshipsForSource?.has(relationshipType)) {
      throw new StixValidationError(
        `Invalid relationship: ${sourceType} cannot have relationship type '${relationshipType}'`
      );
    }

    this.validateRelationshipTarget(sourceType, relationshipType, targetType);
  }

  private validateRelationshipTarget(sourceType: string, relationshipType: string, targetType: string): void {
    const validTargets = new Map([
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
      ['based-on', new Set(['observed-data'])]
    ]);

    const validTargetTypes = validTargets.get(relationshipType);
    if (!validTargetTypes?.has(targetType)) {
      throw new StixValidationError(
        `Invalid relationship target: ${relationshipType} relationship cannot target ${targetType}`
      );
    }
  }

  async findRelatedObjects(objectId: string): Promise<StixRelationship[]> {
    try {
      const { body } = await this.client.search({
        index: this.index,
        body: {
          query: {
            bool: {
              should: [
                { term: { source_ref: objectId } },
                { term: { target_ref: objectId } }
              ],
              minimum_should_match: 1
            }
          }
        }
      });
  
      // Ensure the result is correctly mapped to StixRelationship type
      return body.hits.hits.map((hit) => {
        const source = hit._source;
        return {
          id: hit._id,
          relationship_type: source.relationship_type,
          source_ref: source.source_ref,
          target_ref: source.target_ref,
          type: source.type,
          created: source.created,
          modified: source.modified,
          start_time: source.start_time,
          stop_time: source.stop_time
        } as StixRelationship;
      });
    } catch (error) {
      throw new InternalServerErrorException(`Error fetching related objects: ${error.message}`);
    }
  }
  

  async findExpandedRelatedObjects(objectId: string): Promise<any[]> {
    try {
      // 1️Fetch relationships for the given object ID
      const relationships = await this.findRelatedObjects(objectId);
  
      // 2️Collect unique related object IDs
      const relatedObjectIds = new Set<string>();
      relationships.forEach((rel) => {
        relatedObjectIds.add(rel.source_ref);
        relatedObjectIds.add(rel.target_ref);
      });
  
      // Remove the original object itself
      relatedObjectIds.delete(objectId);
      if (relatedObjectIds.size === 0) return [];
  
      // 3️Handle OpenSearch's `terms` limit (default: 1024 terms)
      const relatedIdsArray = Array.from(relatedObjectIds);
      const chunkSize = 1000; // Adjust based on OpenSearch's `terms` limit
      const results = [];
  
      for (let i = 0; i < relatedIdsArray.length; i += chunkSize) {
        const chunk = relatedIdsArray.slice(i, i + chunkSize);
  
        // 4️Fetch related object details in batches
        const { body } = await this.client.search({
          index: 'stix-objects',
          body: {
            query: {
              terms: { id: chunk }
            }
          }
        });
  
        // 5️Map results
        const chunkResults = body.hits.hits.map((hit) => ({
          id: hit._id,
          ...hit._source,
        }));
  
        results.push(...chunkResults);
      }
  
      return results;
    } catch (error) {
      throw new InternalServerErrorException(
        `Error fetching expanded related objects: ${error.message}`
      );
    }
  }
  



}
