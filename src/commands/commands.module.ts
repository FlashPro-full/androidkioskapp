import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Command } from './entities/command.entity';
import { CommandsService } from './commands.service';
import { CommandsController } from './commands.controller';
import { DevicesModule } from '../devices/devices.module';
import { Device } from '../devices/entities/device.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Command, Device]),
    forwardRef(() => DevicesModule),
  ],
  providers: [CommandsService],
  controllers: [CommandsController],
  exports: [CommandsService],
})
export class CommandsModule {}

