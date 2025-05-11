import { Resolver, Query, InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { IncidentService } from './incident.service';
import { CreateIncidentInput, UpdateIncidentInput } from './incident.input';
import { Incident } from './incident.entity';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Inject } from '@nestjs/common';

@InputType()
export class SearchIncidentInput extends PartialType(CreateIncidentInput){}

@ObjectType()
export class IncidentSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Incident])
  results: Incident[];
}

@Resolver(() => Incident)
export class IncidentResolver  {

  constructor(
            private readonly incidentService: IncidentService,
            @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
          ) { }
        
          // Date conversion helper
          public convertDates(payload: any): Incident {
            const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
            dateFields.forEach(field => {
              if (payload[field]) payload[field] = new Date(payload[field]);
            });
            return payload;
          }
        
          // Subscription Definitions
          @Subscription(() => Incident, {
            name: 'incidentCreated',
            resolve: (payload) => payload,
          })
          incidentCreated() {
            return this.pubSub.asyncIterator('incidentCreated');
          }
        
          @Subscription(() => Incident, {
            name: 'incidentUpdated',
            resolve: (payload) => payload,
          })
          incidentUpdated() {
            return this.pubSub.asyncIterator('incidentUpdated');
          }
        
          @Subscription(() => String, { name: 'incidentDeleted' })
          incidentDeleted() {
            return this.pubSub.asyncIterator('incidentDeleted');
          }
        

  @Mutation(() => Incident)
  async createIncident(
    @Args('input') createIncidentInput: CreateIncidentInput,
  ): Promise<Incident> {
    return this.incidentService.create(createIncidentInput);
  }

  @Query(() => IncidentSearchResult)
  async searchIncidents(
    @Args('filters', { type: () => SearchIncidentInput, nullable: true }) filters: SearchIncidentInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<IncidentSearchResult> {
    return this.incidentService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Incident, { nullable: true })
  async incident(@Args('id') id: string): Promise<Incident> {
    return this.incidentService.findOne(id);
  }

  @Mutation(() => Incident)
  async updateIncident(
    @Args('id') id: string,
    @Args('input') updateIncidentInput: UpdateIncidentInput,
  ): Promise<Incident> {
    return this.incidentService.update(id, updateIncidentInput);
  }

  @Mutation(() => Boolean)
  async deleteIncident(@Args('id') id: string): Promise<boolean> {
    return this.incidentService.remove(id);
  }
}