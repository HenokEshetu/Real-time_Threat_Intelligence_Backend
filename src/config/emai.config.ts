import { registerAs } from '@nestjs/config';

export default registerAs('email', () => ({
  user: process.env.MAIL_USER || 'api',
  host: process.env.MAIL_HOST || '',
  port: process.env.MAIL_PORT || '',
  password: process.env.MAIL_PASSWORD || '',
  from: process.env.MAIL_FROM || '',
}));