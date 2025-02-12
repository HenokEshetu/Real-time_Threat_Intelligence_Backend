// bundle.service.ts

import { Injectable } from '@nestjs/common';
import { Bundle } from './bundle.entity';

@Injectable()
export class BundleService {
    private bundles: Bundle[] = [];

    getAllBundles(): Bundle[] {
        return this.bundles;
    }

    getBundleById(id: string): Bundle | undefined {
        return this.bundles.find(bundle => bundle.id === id);
    }

    addBundle(bundle: Bundle): void {
        this.bundles.push(bundle);
    }

    // Additional methods for updating and deleting bundles can be added
}