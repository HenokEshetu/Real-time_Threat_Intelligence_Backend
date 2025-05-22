import {
  Resolver,
  Query,
  InputType,
  Mutation,
  Args,
  Int,
  ObjectType,
  Field,
  PartialType,
} from '@nestjs/graphql';
import { UserAccountService } from './user-account.service';
import { UserAccount } from './user-account.entity';
import {
  CreateUserAccountInput,
  UpdateUserAccountInput,
} from './user-account.input';
import { BaseStixResolver } from '../../base-stix.resolver';
import { UseGuards } from '@nestjs/common';
import { RolesGuard } from 'src/user-management/guards/roles.guard';
import { Permissions } from 'src/user-management/decorators/permissions.decorator';
import { Permissions as permissions } from 'src/user-management/roles-permissions/permissions';

@InputType()
export class SearchUrlUserAccountInput extends PartialType(
  CreateUserAccountInput,
) {}

@ObjectType()
export class UserAccountSearchResult {
  @Field(() => Int)
  page: number;
  @Field(() => Int)
  pageSize: number;
  @Field(() => Int)
  total: number;
  @Field(() => Int)
  totalPages: number;
  @Field(() => [UserAccount])
  results: UserAccount[];
}

@Resolver(() => UserAccount)
export class UserAccountResolver extends BaseStixResolver(UserAccount) {
  public typeName = ' user-account';
  constructor(private readonly userAccountService: UserAccountService) {
    super();
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.AddAll)
  @Mutation(() => UserAccount)
  async createUserAccount(
    @Args('input') createUserAccountInput: CreateUserAccountInput,
  ): Promise<UserAccount> {
    return this.userAccountService.create(createUserAccountInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => UserAccountSearchResult)
  async searchUserAccounts(
    @Args('filters', { type: () => SearchUrlUserAccountInput, nullable: true })
    filters: SearchUrlUserAccountInput = {},
    @Args('page', { type: () => Int, defaultValue: 1 }) page: number,
    @Args('pageSize', { type: () => Int, defaultValue: 10 }) pageSize: number,
  ): Promise<UserAccountSearchResult> {
    return this.userAccountService.searchWithFilters(filters, page, pageSize);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.ViewAll)
  @Query(() => UserAccount, { nullable: true })
  async userAccount(@Args('id') id: string): Promise<UserAccount> {
    return this.userAccountService.findOne(id);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.UpdateAll)
  @Mutation(() => UserAccount)
  async updateUserAccount(
    @Args('id') id: string,
    @Args('input') updateUserAccountInput: UpdateUserAccountInput,
  ): Promise<UserAccount> {
    return this.userAccountService.update(id, updateUserAccountInput);
  }

  @UseGuards(RolesGuard)
  @Permissions(permissions.STIX.RemoveAll)
  @Mutation(() => Boolean)
  async deleteUserAccount(@Args('id') id: string): Promise<boolean> {
    return this.userAccountService.remove(id);
  }
}
