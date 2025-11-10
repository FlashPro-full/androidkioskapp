import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  Inject,
  Param,
  Patch,
  Post,
  UseGuards,
  forwardRef,
} from '@nestjs/common';
import { DevicesService } from './devices.service';
import { CreateDeviceDto } from './dto/create-device.dto';
import { UpdateDeviceDto } from './dto/update-device.dto';
import { HeartbeatDto } from './dto/heartbeat.dto';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { CommandsService } from '../commands/commands.service';

@Controller('devices')
export class DevicesController {
  constructor(
    private readonly devicesService: DevicesService,
    @Inject(forwardRef(() => CommandsService))
    private readonly commandsService: CommandsService,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get()
  findAll() {
    return this.devicesService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Post()
  async create(@Body() dto: CreateDeviceDto) {
    return this.devicesService.createDevice(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch(':id')
  update(@Param('id') id: string, @Body() dto: UpdateDeviceDto) {
    return this.devicesService.updateDevice(id, dto);
  }

  @Post(':id/heartbeat')
  async heartbeat(
    @Param('id') id: string,
    @Body() dto: HeartbeatDto,
    @Headers('authorization') authHeader?: string,
  ) {
    const token = this.extractBearerToken(authHeader);
    const device = await this.devicesService.authenticateDevice(id, token);
    const heartbeat = await this.devicesService.recordHeartbeat(device, dto);
    const command = await this.commandsService.consumeNextCommand(device.id);
    return { heartbeatId: heartbeat.id, command };
  }

  private extractBearerToken(header?: string): string {
    if (!header || !header.startsWith('Bearer ')) {
      throw new BadRequestException('Missing bearer token');
    }
    return header.substring('Bearer '.length);
  }
}

