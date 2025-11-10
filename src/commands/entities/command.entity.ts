import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Device } from '../../devices/entities/device.entity';

export enum CommandType {
  PIN_UPDATE = 'PIN_UPDATE',
  PACKAGE_UPDATE = 'PACKAGE_UPDATE',
  REBOOT = 'REBOOT',
}

export enum CommandStatus {
  PENDING = 'PENDING',
  DELIVERED = 'DELIVERED',
  ACKNOWLEDGED = 'ACKNOWLEDGED',
}

@Entity({ name: 'commands' })
export class Command {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Device, (device) => device.commands, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'device_id' })
  device: Device;

  @Column({ type: 'enum', enum: CommandType })
  type: CommandType;

  @Column({ type: 'jsonb', nullable: true })
  payload?: Record<string, unknown>;

  @Column({ type: 'enum', enum: CommandStatus, default: CommandStatus.PENDING })
  status: CommandStatus;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}



