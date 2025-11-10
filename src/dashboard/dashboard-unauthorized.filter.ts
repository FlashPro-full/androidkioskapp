import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch(UnauthorizedException)
export class DashboardUnauthorizedFilter implements ExceptionFilter {
  catch(exception: UnauthorizedException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const reason = exception.message ?? 'loginRequired';
    const next = request.originalUrl || request.url || '/dashboard/devices';
    const safeNext = next.startsWith('/') ? next : '/dashboard/devices';

    const params = new URLSearchParams();
    params.set('next', safeNext);
    params.set('message', reason);

    response.redirect(`/dashboard/login?${params.toString()}`);
  }
}

