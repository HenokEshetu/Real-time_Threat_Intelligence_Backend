import { Resolver, Query,InputType, Mutation, Args, Int } from '@nestjs/graphql';
import { NoteService } from './note.service';
import { Note } from './note.entity';
import { CreateNoteInput, UpdateNoteInput } from './note.input';
import { ObjectType, Field } from '@nestjs/graphql';
import { PartialType } from '@nestjs/graphql';

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
export class NoteResolver {
  constructor(private readonly noteService: NoteService) {}

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