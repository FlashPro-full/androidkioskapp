import { Module } from '@nestjs/common';
import { DashboardController } from './dashboard.controller';
import { AuthModule } from '../auth/auth.module';
import { DevicesModule } from '../devices/devices.module';
import { CommandsModule } from '../commands/commands.module';
import { UsersModule } from '../users/users.module';
import { ConfigModule } from '@nestjs/config';
import { DashboardAuthGuard } from './dashboard-auth.guard';

@Module({
  imports: [AuthModule, DevicesModule, CommandsModule, UsersModule, ConfigModule],
  controllers: [DashboardController],
  providers: [DashboardAuthGuard],
})
export class DashboardModule {}

