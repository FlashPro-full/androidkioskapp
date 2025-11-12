import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import express from 'express';
import hbs from 'hbs';
import { join } from 'path';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.setGlobalPrefix('api', {
    exclude: ['', 'dashboard', 'dashboard/(.*)', 'auth/(.*)'],
  });
  app.enableCors();
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json({ limit: '50mb' }));
  app.setBaseViewsDir(join(__dirname, '..', 'views'));
  app.setViewEngine('hbs');
  const viewsDir = join(__dirname, '..', 'views');
  app.setBaseViewsDir(viewsDir);
  hbs.registerPartials(join(viewsDir, 'partials'));
  hbs.registerHelper('pretty', (context: unknown) =>
    JSON.stringify(context, null, 2),
  );
  hbs.registerHelper('year', () => new Date().getFullYear());
  hbs.registerHelper('eq', (a: any, b: any) => a === b);
  hbs.registerHelper('or', (a: any, b: any) => a || b);
  hbs.registerHelper('statusLabel', (status: string) => {
    switch (status) {
      case 'ONLINE':
        return 'Online';
      case 'OFFLINE':
        return 'Offline';
      case 'PROVISIONED':
        return 'Provisioned';
      default:
        return status ?? 'Unknown';
    }
  });
  hbs.registerHelper('statusClass', (status: string) =>
    status ? status.toLowerCase() : 'unknown',
  );
  hbs.registerHelper('formatDate', (value?: string | Date) => {
    if (!value) {
      return 'Never';
    }
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) {
      return typeof value === 'string' ? value : 'Unknown';
    }
    return date.toLocaleString();
  });
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



