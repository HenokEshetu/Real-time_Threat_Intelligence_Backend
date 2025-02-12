// bundle.resolver.ts

import { Resolver, Query, Args, Mutation } from '@nestjs/graphql';
import { BundleService } from './bundle.service';
import { Bundle } from './bundle.entity';
import { BundleInput } from './bundle.input';

@Resolver(() => Bundle)
export class BundleResolver {
    constructor(private readonly bundleService: BundleService) {}

    @Query(() => [Bundle])
    async getBundles(): Promise<Bundle[]> {
        return this.bundleService.getAllBundles();
    }

    @Query(() => Bundle, { nullable: true })
    async getBundle(@Args('id') id: string): Promise<Bundle | undefined> {
        return this.bundleService.getBundleById(id);
    }

    @Mutation(() => Bundle)
    async addBundle(@Args('bundle') bundleInput: BundleInput): Promise<Bundle> {
        const bundle: Bundle = {
            ...bundleInput,
            type: 'bundle', // Ensure the type is set correctly
        };
        this.bundleService.addBundle(bundle);
        return bundle;
    }
}