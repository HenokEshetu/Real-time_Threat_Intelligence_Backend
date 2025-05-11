import { Resolver, Query,InputType, Mutation, Args, Int, Subscription } from '@nestjs/graphql';
import { NoteService } from './note.service';
import { Note } from './note.entity';
import { CreateNoteInput, UpdateNoteInput } from './note.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';
import { PUB_SUB } from 'src/cti_platform/modules/pubsub.module';
import { Inject } from '@nestjs/common';
import { RedisPubSub } from 'graphql-redis-subscriptions';

@InputType()
export class SearchNoteInput extends PartialType(CreateNoteInput){}

@ObjectType()
export class NoteSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [Note])
  results: Note[];
}

@Resolver(() => Note)
export class NoteResolver  {
    constructor(
      private readonly noteService: NoteService,
      @Inject(PUB_SUB) private readonly pubSub: RedisPubSub
    ) { }
  
    // Date conversion helper
    public convertDates(payload: any): Note {
      const dateFields = ['created', 'modified', 'valid_from', 'valid_until'];
      dateFields.forEach(field => {
        if (payload[field]) payload[field] = new Date(payload[field]);
      });
      return payload;
    }
  
    // Subscription Definitions
    @Subscription(() => Note, {
      name: 'noteCreated',
      resolve: (payload) => payload,
    })
    noteCreated() {
      return this.pubSub.asyncIterator('noteCreated');
    }
  
    @Subscription(() => Note, {
      name: 'noteUpdated',
      resolve: (payload) => payload,
    })
    noteUpdated() {
      return this.pubSub.asyncIterator('noteUpdated');
    }
  
    @Subscription(() => String, { name: 'noteDeleted' })
    noteDeleted() {
      
      return this.pubSub.asyncIterator('noteDeleted');
    }
  

  @Mutation(() => Note)
  async createNote(
    @Args('input') createNoteInput: CreateNoteInput,
  ): Promise<Note> {
    return this.noteService.create(createNoteInput);
  }

  @Query(() => NoteSearchResult)
  async searchNotes(
    @Args('filters', { type: () => SearchNoteInput, nullable: true }) filters: SearchNoteInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<NoteSearchResult> {
    return this.noteService.searchWithFilters(filters, page, pageSize);
  }

  @Query(() => Note, { nullable: true })
  async note(@Args('id') id: string): Promise<Note> {
    return this.noteService.findOne(id);
  }

  @Mutation(() => Note)
  async updateNote(
    @Args('id') id: string,
    @Args('input') updateNoteInput: UpdateNoteInput,
  ): Promise<Note> {
    return this.noteService.update(id, updateNoteInput);
  }

  @Mutation(() => Boolean)
  async deleteNote(@Args('id') id: string): Promise<boolean> {
    return this.noteService.remove(id);
  }
}