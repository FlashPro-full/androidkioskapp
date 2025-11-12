import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { Device, DeviceStatus } from './entities/device.entity';
import { DeviceToken } from './entities/device-token.entity';
import { Heartbeat } from './entities/heartbeat.entity';
import { CreateDeviceDto } from './dto/create-device.dto';
import { UpdateDeviceDto } from './dto/update-device.dto';
import { HeartbeatDto } from './dto/heartbeat.dto';
import { generateSalt, hashPin } from '../common/pin.util';
import { randomBytes, createHash } from 'crypto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class DevicesService {
  constructor(
    @InjectRepository(Device)
    private readonly devicesRepository: Repository<Device>,
    @InjectRepository(DeviceToken)
    private readonly tokensRepository: Repository<DeviceToken>,
    @InjectRepository(Heartbeat)
    private readonly heartbeatsRepository: Repository<Heartbeat>,
    private readonly configService: ConfigService,
    private readonly dataSource: DataSource,
  ) {}

  findAll(): Promise<Device[]> {
    return this.devicesRepository.find({
      order: { updatedAt: 'DESC' },
    });
  }

  async createDevice(dto: CreateDeviceDto) {
    const salt = generateSalt();
    const initialPin = dto.initialPin ?? '1234';
    const pinHash = hashPin(initialPin, salt);

    const device = this.devicesRepository.create({
      displayName: dto.displayName,
      allowedPackage: dto.allowedPackage ?? 'com.client.businessapp',
      pinSalt: salt,
      pinHash,
      initialPinPlaintext: initialPin, // Store plaintext for QR regeneration
      expectedDeviceSerial: dto.expectedDeviceSerial,
      status: DeviceStatus.PROVISIONED,
    });
    await this.devicesRepository.save(device);

    const { plainToken, tokenHash } = this.generateDeviceToken();
    const deviceToken = this.tokensRepository.create({
      tokenHash,
      device,
    });
    await this.tokensRepository.save(deviceToken);

    device.latestToken = deviceToken;
    await this.devicesRepository.save(device);

    const provisioning = {
      portal_url: this.configService.get<string>('PORTAL_URL') ?? '',
      device_id: device.id,
      device_token: plainToken,
      allowed_package: device.allowedPackage,
      initial_pin: initialPin,
    };

    return {
      device,
      provisioning,
    };
  }

  async updateDevice(id: string, dto: UpdateDeviceDto): Promise<Device> {
    const device = await this.devicesRepository.findOne({ where: { id } });
    if (!device) {
      throw new NotFoundException(`Device ${id} not found`);
    }

    if (dto.displayName) {
      device.displayName = dto.displayName;
    }
    if (dto.allowedPackage) {
      device.allowedPackage = dto.allowedPackage;
    }
    if (dto.expectedDeviceSerial !== undefined) {
      device.expectedDeviceSerial = dto.expectedDeviceSerial;
    }
    await this.devicesRepository.save(device);
    return device;
  }

  async getDeviceOrThrow(id: string): Promise<Device> {
    const device = await this.devicesRepository.findOne({
      where: { id },
      relations: ['latestToken'],
    });
    if (!device) {
      throw new NotFoundException(`Device ${id} not found`);
    }
    return device;
  }

  async getLatestHeartbeat(deviceId: string): Promise<Heartbeat | null> {
    return this.heartbeatsRepository.findOne({
      where: { device: { id: deviceId } },
      order: { createdAt: 'DESC' },
    });
  }

  async authenticateDevice(deviceId: string, bearerToken: string): Promise<Device> {
    const device = await this.devicesRepository.findOne({
      where: { id: deviceId },
      relations: ['latestToken'],
    });
    if (!device || !device.latestToken) {
      throw new UnauthorizedException('Unknown device or token');
    }

    const hashed = this.hashToken(bearerToken);
    if (device.latestToken.tokenHash !== hashed) {
      throw new UnauthorizedException('Invalid token');
    }
    return device;
  }

  async recordHeartbeat(
    device: Device,
    heartbeatDto: HeartbeatDto,
  ): Promise<Heartbeat> {
    // Validate device serial if expected serial is set
    if (device.expectedDeviceSerial && heartbeatDto.deviceSerial) {
      if (device.expectedDeviceSerial !== heartbeatDto.deviceSerial) {
        throw new UnauthorizedException(
          `Device serial mismatch. Expected: ${device.expectedDeviceSerial}, Got: ${heartbeatDto.deviceSerial}`,
        );
      }
    }

    device.lastCheckIn = new Date();
    device.status = DeviceStatus.ONLINE;
    await this.devicesRepository.save(device);

    const heartbeat = this.heartbeatsRepository.create({
      device,
      batteryLevel: heartbeatDto.batteryLevel,
      wifiSsid: heartbeatDto.wifiSsid,
      deviceSerial: heartbeatDto.deviceSerial,
      notes: heartbeatDto.notes,
    });
    return this.heartbeatsRepository.save(heartbeat);
  }

  async rotatePin(deviceId: string, newPin: string): Promise<Device> {
    const device = await this.getDeviceOrThrow(deviceId);
    const salt = generateSalt();
    const pinHash = hashPin(newPin, salt);
    device.pinSalt = salt;
    device.pinHash = pinHash;
    device.initialPinPlaintext = newPin; // Update stored PIN for QR regeneration
    device.lastCommandAt = new Date();
    await this.devicesRepository.save(device);
    return device;
  }

  async rotateDeviceToken(deviceId: string): Promise<{ token: string }> {
    const device = await this.getDeviceOrThrow(deviceId);
    
    // Load the token relationship if it exists
    const existingToken = await this.tokensRepository.findOne({
      where: { device: { id: deviceId } },
    });
    
    if (existingToken) {
      // Get the foreign key column name from TypeORM metadata
      const deviceMetadata = this.dataSource.getMetadata(Device);
      const latestTokenRelation = deviceMetadata.findRelationWithPropertyPath('latestToken');
      const foreignKeyColumn = latestTokenRelation?.joinColumns?.[0]?.databaseName;
      
      if (foreignKeyColumn) {
        // Use raw SQL to nullify the foreign key column
        await this.dataSource.query(
          `UPDATE devices SET ${foreignKeyColumn} = NULL WHERE id = $1`,
          [deviceId]
        );
      } else {
        // Fallback: try to clear the relationship using TypeORM
        await this.devicesRepository
          .createQueryBuilder()
          .update(Device)
          .set({ latestToken: null as any })
          .where('id = :deviceId', { deviceId })
          .execute();
      }
      
      // Now we can safely delete the token
      await this.tokensRepository.remove(existingToken);
    }

    const { plainToken, tokenHash } = this.generateDeviceToken();
    const token = this.tokensRepository.create({
      device,
      tokenHash,
    });
    await this.tokensRepository.save(token);
    
    // Update device to reference the new token
    device.latestToken = token;
    await this.devicesRepository.save(device);
    return { token: plainToken };
  }

  private generateDeviceToken(): { plainToken: string; tokenHash: string } {
    const plainToken = randomBytes(24).toString('base64url');
    return { plainToken, tokenHash: this.hashToken(plainToken) };
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('base64');
  }
}

