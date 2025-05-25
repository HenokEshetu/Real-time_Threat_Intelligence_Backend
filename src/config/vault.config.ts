import { registerAs } from '@nestjs/config';

export default registerAs('vault', () => ({
  addr: process.env.VAULT_ADDR || 'http://localhost:8200',
  token: process.env.VAULT_TOKEN,
}));
