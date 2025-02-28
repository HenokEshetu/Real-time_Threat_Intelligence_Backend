import { InputType } from '@nestjs/graphql';

import {RelationshipCommonInput} from  '../../../core/types/common-data-types';

@InputType()
export class CreateRelationshipInput extends RelationshipCommonInput {
  
}

@InputType()
export class UpdateRelationshipInput extends RelationshipCommonInput {
  

  
}