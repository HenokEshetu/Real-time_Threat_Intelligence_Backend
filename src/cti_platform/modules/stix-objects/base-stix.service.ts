// base-stix.service.ts
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';
import { PUB_SUB } from '../pubsub.module';

export abstract class BaseStixService<T extends { 
  id: string;
  valid_from?: string | Date; 
  created?: string | Date; 
  modified?: string | Date 
}> {
  protected abstract typeName: string;
  
  constructor(@Inject(PUB_SUB) protected readonly pubSub: RedisPubSub) {}

  protected convertDates(item: T): T {
    const convert = (date: any) => date ? new Date(date).toISOString() : null;
    return {
      ...item,
      valid_from: convert(item.valid_from),
      created: convert(item.created),
      modified: convert(item.modified),
    };
  }

  protected async publishCreated(item: T): Promise<void> {
    await this.pubSub.publish(`${this.typeName}Created`, this.convertDates(item));
  }

  protected async publishUpdated(item: T): Promise<void> {
    await this.pubSub.publish(`${this.typeName}Updated`, this.convertDates(item));
  }

  protected async publishDeleted(id: string): Promise<void> {
    await this.pubSub.publish(`${this.typeName}Deleted`, id);
  }
}