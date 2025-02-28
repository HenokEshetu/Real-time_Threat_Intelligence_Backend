import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Client } from '@opensearch-project/opensearch';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { join } from 'path';

// Import submodules
import { AddStixReportManuallyModule } from './modules/add-stix-report-manually/add-stix-report-manually.module';
import { AlertGenerationModule } from './modules/alert-generation/alert-generation.module';
import { AnalysisAndThreatCorrelationModule } from './modules/analysis-and-threat-correlation/analysis-and-threat-correlation.module';
import { EnrichmentModule } from './modules/enrichment/enrichment.module';
import { ExportStixReportModule } from './modules/export-stix-report/export-stix-report.module';
import { IngestionFromApiFeedsModule } from './modules/ingestion-from-api-feeds/ingestion-from-api-feeds.module';
import { IntegrationModule } from './modules/integration/integration.module';
import { StixObjectsModule } from './modules/stix-objects/stix-objects.module';
import opensearchConfig from './config/opensearch.config';
@Module({
  imports: [
      // Global Configuration
      ConfigModule.forRoot({
        load: [opensearchConfig],
      }),
    ConfigModule, // Ensure ConfigModule is set up correctly
    AddStixReportManuallyModule,
    AlertGenerationModule,
    AnalysisAndThreatCorrelationModule,
    EnrichmentModule,
    ExportStixReportModule,
    IngestionFromApiFeedsModule,
    IntegrationModule,
    StixObjectsModule,

    // GraphQL Configuration with coreSchema.gql
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/coreSchema.gql'),
      sortSchema: true,
      playground: true, // Enable GraphQL playground
      subscriptions: {
        'graphql-ws': true, // Enable WebSockets for real-time updates
      },
      context: ({ req }) => ({ req }),
    }),
  ],
  providers: [
    {
      provide: 'OPENSEARCH_CLIENT',
      useFactory: (configService: ConfigService) => {
        const opensearchHost = configService.get<string>('OPENSEARCH_HOST', 'http://localhost:9200');
        console.log(`[OpenSearch] Connecting to: ${opensearchHost}`);
        return new Client({ node: opensearchHost });
      },
      inject: [ConfigService],
    },
  ],
  exports: ['OPENSEARCH_CLIENT'],
})
export class CtiPlatformModule {}
