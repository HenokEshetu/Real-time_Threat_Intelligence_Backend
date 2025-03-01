import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { APP_GUARD } from '@nestjs/core';
import { JwtAuthGuard } from './user-management/guards/jwt-auth.guard';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { CtiPlatformModule } from './cti_platform/cti_platform.module';
import { UserManagementModule } from './user-management/user-management.module';
import { join } from 'path';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
      sortSchema: true,
      playground: true,
      subscriptions: {
        'graphql-ws': true, // Enable WebSockets for real-time updates
      },
      context: ({ req }) => ({ req }),
    }),
    CtiPlatformModule,
    UserManagementModule,
  ],
  providers: [
    // Apply JWT Auth Guard globally for all routes, including GraphQL
    
      
       // Apply the JwtAuthGuard globally
   
  ],
})
export class AppModule {}
