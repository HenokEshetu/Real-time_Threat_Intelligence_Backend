import { ObjectType, Field } from '@nestjs/graphql';
import { User } from '../entities/user.entity';

@ObjectType()
export class LoginResponse {
  @Field()
  access_token: string;

  @Field(() => User)
  user: User;
}

@ObjectType()
export class TokenPayload {
  @Field()
  sub: string;

  @Field()
  email: string;

  @Field(() => [String])
  roles: string[];
}

@ObjectType()
export class AuthResponse {
  @Field()
  success: boolean;

  @Field({ nullable: true })
  message?: string;
}