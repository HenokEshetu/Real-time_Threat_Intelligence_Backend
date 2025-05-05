// src/opensearch/opensearch.module.ts
import { Global, Module } from '@nestjs/common';
import { Client } from '@opensearch-project/opensearch';

@Global()
@Module({
  providers: [
    {
      provide: 'OPENSEARCH_CLIENT',
      useFactory: () => {
        const clientOptions = {
          node: process.env.OPENSEARCH_NODE || 'http://localhost:9200',
          ssl: process.env.OPENSEARCH_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
          auth: process.env.OPENSEARCH_USERNAME && process.env.OPENSEARCH_PASSWORD
            ? {
                username: process.env.OPENSEARCH_USERNAME,
                password: process.env.OPENSEARCH_PASSWORD,
              }
            : undefined,
        };
        return new Client(clientOptions);
      },
    },
  ],
  exports: ['OPENSEARCH_CLIENT'],
})
export class OpenSearchModule {}