import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS
  app.enableCors({
    origin: '*', // Allow frontend origin
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
  });

  const port = process.env.PORT ?? 4000;
  await app.listen(port);

  console.log(` Server running at http://localhost:${port}`);
  console.log(`GraphQL Playground available at http://localhost:${port}/graphql`);
}
bootstrap();
