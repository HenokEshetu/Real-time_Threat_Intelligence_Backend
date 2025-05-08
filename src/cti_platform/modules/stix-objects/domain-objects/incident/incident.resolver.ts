import { Resolver, Query, InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { IncidentService } from './incident.service';
import { CreateIncidentInput, UpdateIncidentInput } from './incident.input';
import { Incident } from './incident.entity';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { BaseStixResolver } from '../../base-stix.resolver';

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
export class IncidentResolver extends BaseStixResolver(Incident) {
  public typeName = 'incident';
  constructor(private readonly incidentService: IncidentService) {
    super()
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