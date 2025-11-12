import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole, UserStatus } from './entities/user.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
  ) {}

  findByUsername(username: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { username } });
  }

  async createAdminIfMissing(
    username: string,
    plaintextPassword: string,
  ): Promise<void> {
    const existing = await this.findByUsername(username);
    if (existing) {
      this.logger.log(`Admin ${username} already exists`);
      return;
    }

    const passwordHash = await bcrypt.hash(plaintextPassword, 12);
    const user = this.usersRepository.create({
      username,
      passwordHash,
      role: UserRole.ADMIN,
      status: UserStatus.ACTIVE,
    });
    await this.usersRepository.save(user);
    this.logger.log(`Seeded admin user ${username}`);
  }

  async findAll(): Promise<User[]> {
    return this.usersRepository.find({
      order: { createdAt: 'DESC' },
    });
  }

  async findById(id: string): Promise<User | null> {
    return this.usersRepository.findOne({ where: { id } });
  }

  async create(
    username: string,
    plaintextPassword: string,
    role: UserRole = UserRole.VIEWER,
    status: UserStatus = UserStatus.PENDING,
  ): Promise<User> {
    const existing = await this.findByUsername(username);
    if (existing) {
      throw new Error(`User ${username} already exists`);
    }

    const passwordHash = await bcrypt.hash(plaintextPassword, 12);
    const user = this.usersRepository.create({
      username,
      passwordHash,
      role,
      status,
    });
    return this.usersRepository.save(user);
  }

  async update(id: string, updates: { role?: UserRole; password?: string; status?: UserStatus }): Promise<User> {
    const user = await this.findById(id);
    if (!user) {
      throw new Error(`User ${id} not found`);
    }

    if (updates.role !== undefined) {
      user.role = updates.role;
    }
    if (updates.status !== undefined) {
      user.status = updates.status;
    }
    if (updates.password) {
      user.passwordHash = await bcrypt.hash(updates.password, 12);
    }

    return this.usersRepository.save(user);
  }

  async delete(id: string): Promise<void> {
    const user = await this.findById(id);
    if (!user) {
      throw new Error(`User ${id} not found`);
    }
    await this.usersRepository.remove(user);
  }
}



