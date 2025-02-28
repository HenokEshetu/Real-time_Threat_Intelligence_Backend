import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { CtiPlatformModule } from './cti_platform/cti_platform.module';
import { UserManagementModule } from './user-management/user-management.module';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: false, // Disable auto schema generation here
      sortSchema: true,
      playground: true,
      context: ({ req }) => ({ req }),
    }),
    CtiPlatformModule,
    //UserManagementModule,
  ],
})
export class AppModule {}