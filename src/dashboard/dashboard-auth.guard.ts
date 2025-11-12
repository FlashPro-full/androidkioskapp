import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { UsersService } from '../users/users.service';
import { UserStatus } from '../users/entities/user.entity';

@Injectable()
export class DashboardAuthGuard implements CanActivate {
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
      
      // Check database for current user status (in case it was updated)
      const user = await this.usersService.findById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Verify user is still active
      if (user.status !== UserStatus.ACTIVE) {
        throw new UnauthorizedException('Your account is pending approval. Please contact an administrator.');
      }

      // Set user object with current data from database
      (request as any).user = {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status,
      };
      
      return true;
    } catch (err: any) {
      if (err instanceof UnauthorizedException) {
        throw err;
      }
      throw new UnauthorizedException('sessionExpired');
    }
  }
}
