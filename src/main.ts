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
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps, curl)
      if (!origin) {
        callback(null, true);
        return;
      }
  
      const allowedOrigins = process.env.CLIENT_URL?.split(',') || [
        // 'http://localhost:5173',
        // 'http://localhost:5174',
        // 'http://localhost:3000',
        // 'https://studio.apollographql.com',
      ];
  
      // Check if origin is in allowed list
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
  
      // Allow any origin with port 5173
      try {
        const url = new URL(origin);
        if (url.port === '5173') {
          return callback(null, true);
        }
      } catch (e) {
        // Invalid URL format
        return callback(new Error('Invalid origin'), false);
      }
  
      // Block all other origins
      callback(new Error('Not allowed by CORS'), false);
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Accept',
      'Accept-Encoding',
      'Origin',
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'XSRF-TOKEN',
      'X-CSRF-Token',
      'Apollo-Require-Preflight',
    ],
    exposedHeaders: ['XSRF-TOKEN', 'Set-Cookie'],
    credentials: true,
    maxAge: 259200,
    preflightContinue: false,
  });

  // Apply CSRF middleware
  // app.use((req, res, next) => csrfMw.use(req, res, next));

  await app.listen(process.env.PORT || 4000);
}
bootstrap();
