import { registerAs } from '@nestjs/config';

export default registerAs('opensearch', () => ({
  host: process.env.OPENSEARCH_HOST || 'http://localhost:9200',
  ssl: process.env.OPENSEARCH_SSL || false,
  username: process.env.OPENSEARCH_USERNAME || 'admin',
  password: process.env.OPENSEARCH_PASSWORD || 'password',
}));
