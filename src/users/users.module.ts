import { Module, OnModuleInit } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { User } from './entities/user.entity';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UsersService, ConfigService],
  exports: [UsersService],
})
export class UsersModule implements OnModuleInit {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
  ) {}

  async onModuleInit(): Promise<void> {
    const username =
      this.configService.get<string>('ADMIN_USERNAME') ?? 'paulkiosk123';
    const password =
      this.configService.get<string>('ADMIN_PASSWORD') ?? 'paulkiosk123!@#';
    await this.usersService.createAdminIfMissing(username, password);
  }
}



