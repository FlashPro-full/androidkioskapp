import {
  Column,
  CreateDateColumn,
  Entity,
  JoinColumn,
  OneToMany,
  OneToOne,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';
import { Command } from '../../commands/entities/command.entity';
import { DeviceToken } from './device-token.entity';
import { Heartbeat } from './heartbeat.entity';

export enum DeviceStatus {
  ONLINE = 'ONLINE',
  OFFLINE = 'OFFLINE',
  PROVISIONED = 'PROVISIONED',
}

@Entity({ name: 'devices' })
export class Device {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'display_name' })
  displayName: string;

  @Column({ name: 'allowed_package' })
  allowedPackage: string;

  @Column({ name: 'pin_hash' })
  pinHash: string;

  @Column({ name: 'pin_salt' })
  pinSalt: string;

  @Column({ type: 'enum', enum: DeviceStatus, default: DeviceStatus.PROVISIONED })
  status: DeviceStatus;

  @Column({ name: 'last_check_in', type: 'timestamp', nullable: true })
  lastCheckIn?: Date;

  @Column({ name: 'last_command_at', type: 'timestamp', nullable: true })
  lastCommandAt?: Date;

  @OneToMany(() => Command, (command) => command.device)
  commands: Command[];

  @OneToMany(() => Heartbeat, (heartbeat) => heartbeat.device)
  heartbeats: Heartbeat[];

  @OneToOne(() => DeviceToken, (token) => token.device)
  @JoinColumn()
  latestToken?: DeviceToken;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}



