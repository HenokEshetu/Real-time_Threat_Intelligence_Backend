import { Module } from '@nestjs/common';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { CtiPlatformModule } from './cti_platform/cti_platform.module';
import { UserManagementModule } from './user-management/user-management.module';
import { join } from 'path';
import { PubSubModule } from 'src/cti_platform/modules/pubsub.module';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { DateTimeResolver } from 'graphql-scalars';
import { JwtAuthGuard } from './user-management/guards/jwt-auth.guard';
import { APP_GUARD } from '@nestjs/core';
import { CsrfGuard } from './security/csrf.guard';
import vaultConfig from './config/vault.config';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [vaultConfig],
    }),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/schema.gql'),
      sortSchema: true,
      playground: true,
      installSubscriptionHandlers: true,
      formatError: (err) => {
        return {
          message: err.message,
        };
      },
      subscriptions: {
        'subscriptions-transport-ws': {
          path: '/graphql',
          onConnect: () => ({ pubSub: new RedisPubSub(/* options */) }),
        },
      },
      resolvers: { DateTime: DateTimeResolver },
      buildSchemaOptions: {
        scalarsMap: [{ type: Date, scalar: DateTimeResolver }],
      },
      context: ({ req, res, connection }) => {
        if (connection) {
          return connection.context;
        }
        return { req, res, pubSub: new RedisPubSub(/* options */) };
      },
    }),

    PubSubModule,
    CtiPlatformModule,
    UserManagementModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: CsrfGuard },
  ],
})
export class AppModule {}
