import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { CtiPlatformModule } from './cti_platform/cti_platform.module';
import { UserManagementModule } from './user-management/user-management.module';
import { join } from 'path';
import { PubSubModule, PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { DateTimeResolver } from 'graphql-scalars';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
      sortSchema: true,
      playground: true,
      installSubscriptionHandlers: true,
      subscriptions: {
        'subscriptions-transport-ws': {
          path: '/graphql',
          onConnect: () => {
            console.log('WebSocket client connected');
            // Provide pubSub instance into subscription context
            return { pubSub: new RedisPubSub(/* your Redis options */) };
          },
        },
      },
      resolvers: {
        DateTime: DateTimeResolver, // Register DateTime scalar
      },
      buildSchemaOptions: {
        scalarsMap: [
          { type: Date, scalar: DateTimeResolver }, // Map Date type to DateTime scalar
        ],
      },
      // Merge HTTP and WebSocket contexts
      context: ({ req, connection }) => {
        if (connection) {
          // subscription
          return connection.context;
        }
        // query / mutation
        return { req, pubSub: new RedisPubSub(/* your Redis options */) };
      },
    }),
    PubSubModule,
    CtiPlatformModule,
    UserManagementModule,
  ],
  providers: [],
})
export class AppModule {}
