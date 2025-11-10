import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { DevicesModule } from './devices/devices.module';
import { CommandsModule } from './commands/commands.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { Device } from './devices/entities/device.entity';
import { Command } from './commands/entities/command.entity';
import { User } from './users/entities/user.entity';
import { DeviceToken } from './devices/entities/device-token.entity';
import { Heartbeat } from './devices/entities/heartbeat.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '.env.local'],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => {
        const dbUrl = configService.get<string>('DB_URL');
        const dbPort = configService.get<string>('DB_PORT');
        const useSsl =
          configService.get<string>('DB_SSL', 'false') === 'true' || !!dbUrl;
        return {
          type: 'postgres',
          url: dbUrl,
          host: dbUrl ? undefined : configService.get<string>('DB_HOST'),
          port: dbUrl ? undefined : dbPort ? parseInt(dbPort, 10) : undefined,
          username: dbUrl ? undefined : configService.get<string>('DB_USER'),
          password: dbUrl ? undefined : configService.get<string>('DB_PASS'),
          database: dbUrl ? undefined : configService.get<string>('DB_NAME'),
          entities: [User, Device, Command, DeviceToken, Heartbeat],
          synchronize:
            configService.get<string>('DB_SYNCHRONIZE', 'false') === 'true',
          ssl: useSsl ? { rejectUnauthorized: false } : false,
          logging: configService.get<boolean>('DB_LOGGING', false),
        };
      },
      inject: [ConfigService],
    }),
    AuthModule,
    UsersModule,
    DevicesModule,
    CommandsModule,
    DashboardModule,
  ],
})
export class AppModule {}



