import { Resolver, Query,InputType, Mutation, Args } from '@nestjs/graphql';
import { UserAccountService } from './user-account.service';
import { UserAccount } from './user-account.entity';
import { CreateUserAccountInput, UpdateUserAccountInput } from './user-account.input';
import { PartialType } from '@nestjs/graphql';

@InputType()
export class SearchUrlUserAccountInput extends PartialType(CreateUserAccountInput) {}

@Resolver(() => UserAccount)
export class UserAccountResolver {
  constructor(private readonly userAccountService: UserAccountService) {}

  @Query(() => UserAccount, { description: 'Search User Accounts with dynamic filters and pagination' })
  async searchUserAccounts(
    @Args('searchParams', { type: () => SearchUrlUserAccountInput, nullable: true }) searchParams?: Partial<SearchUrlUserAccountInput>,
    @Args('page', { type: () => Number, defaultValue: 1 }) page?: number,
    @Args('pageSize', { type: () => Number, defaultValue: 10 }) pageSize?: number
  ): Promise<any> {
    return this.userAccountService.searchWithFilters(searchParams || {}, page, pageSize);
  }

  @Query(() => UserAccount)
  async userAccount(@Args('id') id: string): Promise<UserAccount> {
    return this.userAccountService.findOne(id);
  }

  @Mutation(() => UserAccount)
  async createUserAccount(
    @Args('createUserAccountInput') createUserAccountInput: CreateUserAccountInput,
  ): Promise<UserAccount> {
    return this.userAccountService.create(createUserAccountInput);
  }

  @Mutation(() => UserAccount)
  async updateUserAccount(
    @Args('id') id: string,
    @Args('updateUserAccountInput') updateUserAccountInput: UpdateUserAccountInput,
  ): Promise<UserAccount> {
    return this.userAccountService.update(id, updateUserAccountInput);
  }

  @Mutation(() => Boolean)
  async removeUserAccount(@Args('id') id: string): Promise<boolean> {
    return this.userAccountService.remove(id);
  }
}