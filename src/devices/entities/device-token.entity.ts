import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  OneToOne,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Device } from './device.entity';

@Entity({ name: 'device_tokens' })
export class DeviceToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'token_hash' })
  tokenHash: string;

  @Column({ name: 'expires_at', type: 'timestamp', nullable: true })
  expiresAt?: Date;

  @OneToOne(() => Device, (device) => device.latestToken, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'device_id' })
  device: Device;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}



