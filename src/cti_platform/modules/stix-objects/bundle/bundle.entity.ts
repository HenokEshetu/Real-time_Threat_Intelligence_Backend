// bundle.entity.ts

import { ObjectType, Field, ID } from '@nestjs/graphql';

@ObjectType()
export class Bundle {
    @Field()
    type: string; // "bundle"

    @Field(() => ID)
    id: string; // Unique identifier for the bundle

    @Field(() => [Object], { nullable: 'itemsAndList' })
    objects?: any[]; // List of STIX Objects
}