import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  ManyToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Device } from './device.entity';

@Entity({ name: 'heartbeats' })
export class Heartbeat {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @ManyToOne(() => Device, (device) => device.heartbeats, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'device_id' })
  device: Device;

  @Column({ name: 'battery_level', nullable: true })
  batteryLevel?: number;

  @Column({ name: 'wifi_ssid', nullable: true })
  wifiSsid?: string;

  @Column({ name: 'notes', nullable: true })
  notes?: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}



