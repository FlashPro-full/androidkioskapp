import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { UsersService } from '../users/users.service';
import { UserStatus } from '../users/entities/user.entity';

@Injectable()
export class DashboardAuthGuard implements CanActivate {
  private readonly logger = new Logger(DashboardAuthGuard.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly usersService: UsersService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token =
      request.cookies?.session_token || request.signedCookies?.session_token;

    if (!token) {
      throw new UnauthorizedException('loginRequired');
    }

    try {
      const payload = await this.jwtService.verifyAsync(token);
      this.logger.debug(`JWT verified for user ID: ${payload.sub}`);
      
      // Check database for current user status (in case it was updated)
      const user = await this.usersService.findById(payload.sub);
      if (!user) {
        this.logger.warn(`User not found in database: ${payload.sub}`);
        throw new UnauthorizedException('User not found');
      }

      this.logger.debug(`User ${user.username} status: ${user.status}`);

      // Verify user is still active
      if (user.status !== UserStatus.ACTIVE) {
        this.logger.warn(`User ${user.username} is not ACTIVE, status: ${user.status} (type: ${typeof user.status})`);
        throw new UnauthorizedException('Your account is pending approval. Please contact an administrator.');
      }

      // Set user object with current data from database
      (request as any).user = {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status,
      };
      
      this.logger.debug(`User ${user.username} authenticated successfully`);
      return true;
    } catch (err: any) {
      if (err instanceof UnauthorizedException) {
        this.logger.debug(`Unauthorized: ${err.message}`);
        throw err;
      }
      this.logger.error(`Error in DashboardAuthGuard: ${err.message}`, err.stack);
      throw new UnauthorizedException('sessionExpired');
    }
  }
}
