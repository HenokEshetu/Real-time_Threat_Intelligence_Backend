import { Resolver, Mutation, Args, Context } from '@nestjs/graphql';
import { AuthService } from '../services/auth/auth.service';
import { Public } from '../decorators/public.decorator';
import { Response, Request as ExpressRequest } from 'express';
import { AuthResponse, LoginResponse } from '../types/auth.types';
import { LoginDto } from '../dto/login.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { VaultService } from 'src/security/vault.service';

@Resolver()
export class AuthResolver {
  constructor(
    private readonly authService: AuthService,
    private readonly vaultService: VaultService,
  ) {}

  @Mutation(() => LoginResponse)
  @Public()
  async login(
    @Args('input') loginDto: LoginDto,
    @Context() { res }: { res: Response },
  ): Promise<LoginResponse> {
    const response = await this.authService.login(loginDto);

    const { jwt_refresh_expires_in: expiresIn } =
      await this.vaultService.getSecret('encryption/data/jwt');

    res.cookie('refresh_token', response.refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: parseInt(expiresIn.replace('d', '')) * 24 * 60 * 60 * 1000,
      path: '/',
    });

    return {
      access_token: response.access_token,
      refresh_token: response.refresh_token,
      user: response.user,
    };
  }

  @Mutation(() => LoginResponse)
  @Public()
  async refreshToken(
    @Context() { req, res }: { req: ExpressRequest; res: Response },
  ): Promise<LoginResponse> {
    const refreshToken = req.cookies?.refresh_token;
    const response = await this.authService.refreshToken(refreshToken);

    return {
      access_token: response.access_token,
      refresh_token: refreshToken,
      user: response.user,
    };
  }

  @Mutation(() => AuthResponse)
  async signOut(
    @Context() { req, res }: { req: ExpressRequest; res: Response },
  ): Promise<AuthResponse> {
    const accessToken = req.headers['authorization']?.split(' ')[1];
    const refreshToken = req.cookies?.refresh_token;

    await this.authService.signOut(accessToken);
    await this.authService.signOut(refreshToken);

    res.clearCookie('refresh_token');
    return { success: true, message: 'Signed out successfully' };
  }

  @Mutation(() => AuthResponse)
  async changePassword(
    @Args('input') changePasswordDto: ChangePasswordDto,
    @Context() context,
  ): Promise<AuthResponse> {
    await this.authService.changePassword(
      context.req.user.id,
      changePasswordDto,
    );
    return {
      success: true,
      message: 'Password changed successfully',
    };
  }
}
