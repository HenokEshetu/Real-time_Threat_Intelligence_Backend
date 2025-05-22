import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { CsrfMiddleware } from './security/csrf.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // const csrfMw = new CsrfMiddleware();

  app.use(
    helmet({
      contentSecurityPolicy:
        process.env.NODE_ENV === 'production' ? undefined : false,
      crossOriginEmbedderPolicy: false,
    }),
  );

  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));

  app.enableCors({
    origin: process.env.CLIENT_URL?.split(',') || [
      'http://localhost:5173', // Default Vite frontend
      'http://localhost:3000', // Common Create-React-App port
      'https://studio.apollographql.com', // GraphQL IDE
    ],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'XSRF-TOKEN',
      'Apollo-Require-Preflight',
    ],
    exposedHeaders: ['XSRF-TOKEN'],
    credentials: true,
    maxAge: 259200, // 72-hour preflight cache
    preflightContinue: false,
  });

  // Apply CSRF middleware
  // app.use((req, res, next) => csrfMw.use(req, res, next));

  await app.listen(process.env.PORT || 4000);
}
bootstrap();
