import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import express from 'express';
import * as hbs from 'hbs';
import { join } from 'path';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.setGlobalPrefix('api', {
    exclude: ['', 'dashboard', 'dashboard/(.*)', 'auth/(.*)'],
  });
  app.enableCors();
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: true }));
  app.setBaseViewsDir(join(__dirname, '..', 'views'));
  app.setViewEngine('hbs');
  const viewsDir = join(__dirname, '..', 'views');
  app.setBaseViewsDir(viewsDir);
  hbs.registerPartials(join(viewsDir, 'partials'));
  hbs.registerHelper('pretty', (context: unknown) =>
    JSON.stringify(context, null, 2),
  );
  hbs.registerHelper('year', () => new Date().getFullYear());
  app.setViewEngine('hbs');
  app.useStaticAssets(join(__dirname, '..', 'public'));

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`Kiosk portal running on port ${port}`);
}

bootstrap();



