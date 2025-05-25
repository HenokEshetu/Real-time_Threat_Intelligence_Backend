import { ObjectType, Field } from '@nestjs/graphql';
import { User } from '../entities/user.entity';

@ObjectType()
export class LoginResponse {
  @Field()
  access_token: string;

  @Field()
  refresh_token: string;

  @Field(() => User)
  user: User;
}

@ObjectType()
export class TokenPayload {
  @Field()
  sub: string;

  @Field()
  email: string;

  @Field()
  role: string;

  @Field()
  token_type: 'access' | 'refresh';
}

@ObjectType()
export class AuthResponse {
  @Field()
  success: boolean;

  @Field({ nullable: true })
  message?: string;
}

export type TokenType = 'access' | 'refresh';
