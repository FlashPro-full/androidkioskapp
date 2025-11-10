import { Inject, Injectable, NotFoundException, forwardRef } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  Command,
  CommandStatus,
  CommandType,
} from './entities/command.entity';
import { DevicesService } from '../devices/devices.service';
import { Device } from '../devices/entities/device.entity';

@Injectable()
export class CommandsService {
  constructor(
    @InjectRepository(Command)
    private readonly commandsRepository: Repository<Command>,
    @Inject(forwardRef(() => DevicesService))
    private readonly devicesService: DevicesService,
    @InjectRepository(Device)
    private readonly devicesRepository: Repository<Device>,
  ) {}

  async queueCommand(
    deviceId: string,
    type: CommandType,
    payload: Record<string, unknown> = {},
  ): Promise<Command> {
    const device = await this.devicesService.getDeviceOrThrow(deviceId);
    const command = this.commandsRepository.create({
      device,
      type,
      payload,
      status: CommandStatus.PENDING,
    });
    device.lastCommandAt = new Date();
    await this.devicesRepository.save(device);
    await this.commandsRepository.save(command);
    return command;
  }

  async consumeNextCommand(deviceId: string): Promise<Command | null> {
    const command = await this.commandsRepository.findOne({
      where: { device: { id: deviceId }, status: CommandStatus.PENDING },
      order: { createdAt: 'ASC' },
    });

    if (!command) {
      return null;
    }

    command.status = CommandStatus.DELIVERED;
    await this.commandsRepository.save(command);
    return command;
  }

  async acknowledgeCommand(deviceId: string, commandId: string): Promise<void> {
    const command = await this.commandsRepository.findOne({
      where: { id: commandId, device: { id: deviceId } },
    });
    if (!command) {
      throw new NotFoundException('Command not found');
    }

    command.status = CommandStatus.ACKNOWLEDGED;
    await this.commandsRepository.save(command);
  }

  async listCommands(deviceId: string): Promise<Command[]> {
    return this.commandsRepository.find({
      where: { device: { id: deviceId } },
      order: { createdAt: 'DESC' },
    });
  }
}

