import { Field, ObjectType } from '@nestjs/graphql';
import { Entity, Column } from 'typeorm';
import { CommonProperties, RelationshipCommonProperties } from '../../../../core/types/common-data-types';


@ObjectType()
export class CourseOfAction extends CommonProperties {
  @Field(() => String)
  
  type: string = 'course-of-action';

  @Field(() => String)
  
  name: string;

  @Field(() => String, { nullable: true })
 
  description?: string;

  @Field(() => String, { nullable: true })

  action?: string;

  @Field(() => String, { nullable: true })
 
  action_type?: string;

  @Field(() => String, { nullable: true })
  
  action_bin?: string;

  @Field(() => String, { nullable: true })
  
  action_reference?: string;

  @Field(() => [RelationshipCommonProperties], { nullable: true })
          relationship?: RelationshipCommonProperties[];
}