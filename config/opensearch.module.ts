import { Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Client } from '@opensearch-project/opensearch';

@Global()
@Module({
  providers: [
    {
      provide: 'OPENSEARCH_CLIENT',
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const clientOptions = {
          node:
            configService.get<string>('opensearch.host') ||
            'http://localhost:9200',
          ssl:
            configService.get<boolean>('opensearch.ssl') === true
              ? { rejectUnauthorized: false }
              : undefined,
          auth:
            configService.get<string>('opensearch.username') &&
            configService.get<string>('opensearch.password')
              ? {
                  username: configService.get<string>('opensearch.username'),
                  password: configService.get<string>('opensearch.password'),
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
