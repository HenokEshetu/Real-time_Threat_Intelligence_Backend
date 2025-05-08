import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Allow ALL origins (for testing only)
  app.enableCors({
    origin: true,  
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
  });

  const port = 3000;
  await app.listen(port, '0.0.0.0'); // Listen on all network interfaces

  console.log(`
   Backend is running on:
  - Local: http://localhost:${port}
  - Network: http://10.161.173.25:${port}
  - GraphQL Playground: http://10.161.173.25:${port}/graphql
  `);
}
bootstrap();