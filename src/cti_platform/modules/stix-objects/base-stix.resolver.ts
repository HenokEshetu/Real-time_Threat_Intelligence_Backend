// base-stix.resolver.ts
import { Resolver, Subscription, Context } from '@nestjs/graphql';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { ClassType } from 'type-graphql';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';

export function BaseStixResolver<T extends object>(classRef: ClassType<T>) {
  @Resolver({ isAbstract: true })
  abstract class BaseStixResolver {
    public abstract typeName: string;

    public convertDates(payload: any): T {
      const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
      dateFields.forEach((field) => {
        if (payload[field]) payload[field] = new Date(payload[field]);
      });
      return payload;
    }

    @UseGuards(RolesGuard)
    @Permissions(permissions.STIX.AddAll)
    @Subscription(() => classRef, {
      name: 'created',
      resolve: function (payload) {
        return this.convertDates(payload);
      },
    })
    created(@Context() context: { pubSub: RedisPubSub }) {
      return context.pubSub.asyncIterator(`${this.typeName}Created`);
    }

    @UseGuards(RolesGuard)
    @Permissions(permissions.STIX.UpdateAll)
    @Subscription(() => classRef, {
      name: 'updated',
      resolve: function (payload) {
        return this.convertDates(payload);
      },
    })
    updated(@Context() context: { pubSub: RedisPubSub }) {
      return context.pubSub.asyncIterator(`${this.typeName}Updated`);
    }

    @UseGuards(RolesGuard)
    @Permissions(permissions.STIX.RemoveAll)
    @Subscription(() => String, { name: 'deleted' })
    deleted(@Context() context: { pubSub: RedisPubSub }) {
      return context.pubSub.asyncIterator(`${this.typeName}Deleted`);
    }
  }

  return BaseStixResolver;
}
