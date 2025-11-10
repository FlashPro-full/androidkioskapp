import {
  Body,
  Controller,
  Get,
  Inject,
  Param,
  Post,
  UseGuards,
  forwardRef,
  BadRequestException,
  Headers,
} from '@nestjs/common';
import { CommandsService } from './commands.service';
import { CreateCommandDto } from './dto/create-command.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CommandType } from './entities/command.entity';
import { DevicesService } from '../devices/devices.service';

@Controller('devices/:deviceId/commands')
export class CommandsController {
  constructor(
    private readonly commandsService: CommandsService,
    @Inject(forwardRef(() => DevicesService))
    private readonly devicesService: DevicesService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  list(@Param('deviceId') deviceId: string) {
    return this.commandsService.listCommands(deviceId);
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  async create(
    @Param('deviceId') deviceId: string,
    @Body() dto: CreateCommandDto,
  ) {
    let payload: Record<string, unknown> = {};
    switch (dto.type) {
      case CommandType.PIN_UPDATE:
        if (!dto.pin) {
          throw new BadRequestException('PIN is required for PIN_UPDATE command');
        }
        const updatedDevice = await this.devicesService.rotatePin(
          deviceId,
          dto.pin,
        );
        payload = {
          pin_hash: updatedDevice.pinHash,
          pin_salt: updatedDevice.pinSalt,
        };
        break;
      case CommandType.PACKAGE_UPDATE:
        if (!dto.allowedPackage) {
          throw new BadRequestException('allowedPackage is required for PACKAGE_UPDATE');
        }
        await this.devicesService.updateDevice(deviceId, {
          allowedPackage: dto.allowedPackage,
        });
        payload = { allowed_package: dto.allowedPackage };
        break;
      case CommandType.REBOOT:
        payload = {};
        break;
      default:
        payload = {};
    }

    return this.commandsService.queueCommand(deviceId, dto.type, payload);
  }

  @Post(':commandId/ack')
  async acknowledge(
    @Param('deviceId') deviceId: string,
    @Param('commandId') commandId: string,
    @Headers('authorization') authHeader?: string,
  ) {
    const token = this.extractBearerToken(authHeader);
    await this.devicesService.authenticateDevice(deviceId, token);
    await this.commandsService.acknowledgeCommand(deviceId, commandId);
    return { status: 'ok' };
  }

  private extractBearerToken(header?: string): string {
    if (!header || !header.startsWith('Bearer ')) {
      throw new BadRequestException('Missing bearer token');
    }
    return header.substring('Bearer '.length);
  }
}

