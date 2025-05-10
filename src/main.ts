import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { UnauthorizedExceptionFilter } from './gql-exception.filter';

async function bootstrap() {
 
// src/main.ts
const app = await NestFactory.create(AppModule);
if (process.env.status === 'production') {
  app.useGlobalFilters(new UnauthorizedExceptionFilter());
  app.useLogger(['error', 'warn']); // Disable verbose logging
}
  // Allow ALL origins (for testing only)
  app.enableCors({
    origin: true,  
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
  });

  const port = 4000;
  await app.listen(port, '0.0.0.0'); // Listen on all network interfaces

  console.log(`
   Backend is running on:
  - Local: http://localhost:${port}
  - Network: http://10.161.173.25:${port}
  - GraphQL Playground: http://10.161.173.25:${port}/graphql
  `);
}
bootstrap();