import { Resolver, Query, InputType, Mutation, Args } from '@nestjs/graphql';
import { IncidentService } from './incident.service';
import { CreateIncidentInput, UpdateIncidentInput } from './incident.input';
import { Incident } from './incident.entity';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchIncidentInput extends PartialType(CreateIncidentInput){}



@Resolver(() => Incident)
export class IncidentResolver {
  constructor(private readonly incidentService: IncidentService) {}

  // Create a new incident
  @Mutation(() => Incident)
  async createIncident(@Args('input') input: CreateIncidentInput): Promise<Incident> {
    return this.incidentService.create(input);
  }

  // Fetch an incident by ID
  @Query(() => Incident, { nullable: true })
  async getIncident(@Args('id') id: string): Promise<Incident> {
    return this.incidentService.findOne(id);
  }

  // Update an existing incident
  @Mutation(() => Incident)
  async updateIncident(
    @Args('id') id: string,
    @Args('input') input: UpdateIncidentInput,
  ): Promise<Incident> {
    return this.incidentService.update(id, input);
  }

  // Delete an incident
  @Mutation(() => Boolean)
  async removeIncident(@Args('id') id: string): Promise<boolean> {
    return this.incidentService.remove(id);
  }

  // Search incidents with filters
  @Query(() => [Incident])
async searchIncidents(
  @Args('filters', { type: () => SearchIncidentInput, nullable: true }) filters?: SearchIncidentInput,
  @Args('page', { type: () => Number, nullable: true, defaultValue: 1 }) page?: number,
  @Args('pageSize', { type: () => Number, nullable: true, defaultValue: 10 }) pageSize?: number,
): Promise<Incident[]> {
  return this.incidentService.searchIncidentWithFilters(filters, page, pageSize);
}

}
