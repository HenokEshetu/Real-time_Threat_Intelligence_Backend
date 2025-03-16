import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { NoteService } from './note.service';
import { Note } from './note.entity';
import { CreateNoteInput, UpdateNoteInput } from './note.input';


import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchNoteInput extends PartialType(CreateNoteInput){}



@Resolver(() => Note)
export class NoteResolver {
  constructor(private readonly noteService: NoteService) {}

  @Mutation(() => Note)
  async createNote(@Args('createNoteInput') createNoteInput: CreateNoteInput): Promise<Note> {
    return this.noteService.create(createNoteInput);
  }

  @Query(() => Note, { nullable: true })
  async getNoteById(@Args('id') id: string): Promise<Note> {
    return this.noteService.findOne(id);
  }

  @Mutation(() => Note)
  async updateNote(
    @Args('id') id: string,
    @Args('updateNoteInput') updateNoteInput: UpdateNoteInput,
  ): Promise<Note> {
    return this.noteService.update(id, updateNoteInput);
  }

  @Mutation(() => Boolean)
  async removeNote(@Args('id') id: string): Promise<boolean> {
    return this.noteService.remove(id);
  }

  @Query(() => [Note])
  async searchNotesWithFilters(
    @Args('filters', { type: () => SearchNoteInput, nullable: true }) filters?: SearchNoteInput,
    @Args('page', { type: () => Number, nullable: true, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, nullable: true, defaultValue: 10 }) pageSize?: number,
  ): Promise<Note[]> {
    const result = await this.noteService.searchNoteWithFilters(filters, page, pageSize);
    return result.results;
  }
}
