import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DevicesService } from './devices.service';
import { DevicesController } from './devices.controller';
import { Device } from './entities/device.entity';
import { DeviceToken } from './entities/device-token.entity';
import { Heartbeat } from './entities/heartbeat.entity';
import { CommandsModule } from '../commands/commands.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Device, DeviceToken, Heartbeat]),
    forwardRef(() => CommandsModule),
  ],
  controllers: [DevicesController],
  providers: [DevicesService],
  exports: [DevicesService],
})
export class DevicesModule {}

