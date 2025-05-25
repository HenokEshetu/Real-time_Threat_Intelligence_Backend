import { Injectable } from '@nestjs/common';
import { JwtOptionsFactory, JwtModuleOptions } from '@nestjs/jwt';
import { VaultService } from 'src/security/vault.service';

@Injectable()
export class JwtConfigService implements JwtOptionsFactory {
  constructor(private vault: VaultService) {}

  async createJwtOptions(): Promise<JwtModuleOptions> {
    const secret = await this.vault
      .getSecret('encryption/data/jwt')
      .then((secret) => secret.jwtAccessSecret);
    return {
      secret: secret,
      signOptions: { expiresIn: '15m' },
    };
  }
}
