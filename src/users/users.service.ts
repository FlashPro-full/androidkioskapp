import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './entities/user.entity';
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
    });
    await this.usersRepository.save(user);
    this.logger.log(`Seeded admin user ${username}`);
  }
}



