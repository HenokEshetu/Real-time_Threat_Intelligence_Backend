// bundle.input.ts

import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class BundleInput {
    @Field()
    id: string; // Unique identifier for the bundle

    @Field(() => [Object], { nullable: 'itemsAndList' })
    objects?: any[]; // List of STIX Objects
}