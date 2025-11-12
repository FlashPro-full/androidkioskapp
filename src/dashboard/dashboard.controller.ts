import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseFilters,
  UseGuards,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from '../auth/auth.service';
import { DevicesService } from '../devices/devices.service';
import { CommandsService } from '../commands/commands.service';
import { DashboardAuthGuard } from './dashboard-auth.guard';
import { CommandType } from '../commands/entities/command.entity';
import { JwtService } from '@nestjs/jwt';
import { DashboardUnauthorizedFilter } from './dashboard-unauthorized.filter';
import { CreateDeviceDto } from '../devices/dto/create-device.dto';
import { generateProvisioningQr } from './provisioning-qr';

const SESSION_COOKIE = 'session_token';

@UseFilters(DashboardUnauthorizedFilter)
@Controller()
export class DashboardController {
  private readonly isProduction = process.env.NODE_ENV === 'production';

  constructor(
    private readonly authService: AuthService,
    private readonly devicesService: DevicesService,
    private readonly commandsService: CommandsService,
    private readonly jwtService: JwtService,
  ) {}

  @Get('/')
  async root(@Res() res: Response) {
    return res.redirect('/dashboard/devices');
  }

  @Get('/dashboard/login')
  async showLogin(@Req() req: Request, @Res() res: Response) {
    const nextParam =
      typeof req.query.next === 'string' ? req.query.next : '/dashboard/devices';
    const safeNext = nextParam.startsWith('/') ? nextParam : '/dashboard/devices';

    if (await this.hasValidSession(req)) {
      return res.redirect(safeNext);
    }

    const messageKey =
      typeof req.query.message === 'string' ? req.query.message : undefined;
    const messages: Record<string, string> = {
      loginRequired: 'Please sign in to continue.',
      sessionExpired: 'Your session expired. Please sign in again.',
      loggedOut: 'You have been signed out.',
    };

    return res.render('auth/login', {
      title: 'Login',
      message: messageKey ? messages[messageKey] : undefined,
      next: safeNext,
    });
  }

  @Post('/dashboard/login')
  async handleLogin(
    @Body('username') username: string,
    @Body('password') password: string,
    @Body('next') next: string | undefined,
    @Res() res: Response,
  ) {
    try {
      const { accessToken } = await this.authService.login(username, password);
      res.cookie(SESSION_COOKIE, accessToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: this.isProduction,
        maxAge: 1000 * 60 * 60, // 1 hour
      });
      const redirectTarget =
        next && next.startsWith('/') ? next : '/dashboard/devices';
      return res.redirect(redirectTarget);
    } catch (error) {
      return res.render('auth/login', {
        title: 'Login',
        error: 'Invalid credentials',
        username,
        next: next && next.startsWith('/') ? next : '/dashboard/devices',
      });
    }
  }

  @Get('/dashboard/logout')
  async logout(@Res() res: Response) {
    res.clearCookie(SESSION_COOKIE);
    return res.redirect('/dashboard/login?message=loggedOut');
  }

  @UseGuards(DashboardAuthGuard)
  @Get('/dashboard/devices')
  async listDevices(
    @Query('status') status: string | undefined,
    @Query('message') message: string | undefined,
    @Res() res: Response,
  ) {
    const devices = await this.devicesService.findAll();
    return res.render('devices/list', {
      title: 'Devices',
      devices,
      status,
      message,
    });
  }

  @UseGuards(DashboardAuthGuard)
  @Post('/dashboard/devices/bulk/commands')
  async queueBulkCommand(
    @Body('deviceIds') deviceIds: string[],
    @Body('action') action: string,
    @Body('pin') pin: string | undefined,
    @Body('allowedPackage') allowedPackage: string | undefined,
    @Res() res: Response,
  ) {
    if (!Array.isArray(deviceIds) || deviceIds.length === 0) {
      return res.redirect(
        '/dashboard/devices?message=' +
          encodeURIComponent('Select at least one device'),
      );
    }
    try {
      switch (action) {
        case 'pin':
          if (!pin || pin.length < 4) {
            return res.redirect(
              '/dashboard/devices?message=' +
                encodeURIComponent('PIN must be at least 4 digits'),
            );
          }
          for (const id of deviceIds) {
            const updatedDevice = await this.devicesService.rotatePin(id, pin);
            await this.commandsService.queueCommand(id, CommandType.PIN_UPDATE, {
              pin_hash: updatedDevice.pinHash,
              pin_salt: updatedDevice.pinSalt,
            });
          }
          break;
        case 'package':
          if (!allowedPackage) {
            return res.redirect(
              '/dashboard/devices?message=' +
                encodeURIComponent('Package name is required'),
            );
          }
          for (const id of deviceIds) {
            await this.devicesService.updateDevice(id, {
              allowedPackage,
            });
            await this.commandsService.queueCommand(
              id,
              CommandType.PACKAGE_UPDATE,
              { allowed_package: allowedPackage },
            );
          }
          break;
        case 'reboot':
          await this.commandsService.queueBulkCommands(
            deviceIds,
            CommandType.REBOOT,
          );
          break;
        default:
          return res.redirect(
            '/dashboard/devices?message=' +
              encodeURIComponent('Unknown bulk action'),
          );
      }
      return res.redirect(
        '/dashboard/devices?message=' +
          encodeURIComponent('Bulk command queued'),
      );
    } catch (error) {
      return res.redirect(
        '/dashboard/devices?message=' +
          encodeURIComponent('Failed to queue bulk command'),
      );
    }
  }

  @UseGuards(DashboardAuthGuard)
  @Get('/dashboard/devices/new')
  async showCreateDevice(
    @Query('status') status: string | undefined,
    @Res() res: Response,
  ) {
    return res.render('devices/new', {
      title: 'Register Device',
      status,
      defaults: {
        allowedPackage:
          process.env.DEFAULT_ALLOWED_PACKAGE ?? 'com.client.businessapp',
      },
    });
  }

  @UseGuards(DashboardAuthGuard)
  @Post('/dashboard/devices/new')
  async createDevice(
    @Body('displayName') displayName: string,
    @Body('allowedPackage') allowedPackage: string | undefined,
    @Body('initialPin') initialPin: string | undefined,
    @Res() res: Response,
  ) {
    const trimmedName = displayName?.trim();
    if (!trimmedName) {
      return res.redirect(
        '/dashboard/devices/new?status=' +
          encodeURIComponent('Device name is required'),
      );
    }

    const dto: CreateDeviceDto = {
      displayName: trimmedName,
      allowedPackage:
        allowedPackage?.trim() ||
        process.env.DEFAULT_ALLOWED_PACKAGE ||
        'com.client.businessapp',
      initialPin: initialPin?.trim(),
    };

    try {
      const result = await this.devicesService.createDevice(dto);
      const params = new URLSearchParams();
      params.set('status', 'Device registered');
      params.set('token', result.provisioning.device_token);
      return res.redirect(
        `/dashboard/devices/${result.device.id}?${params.toString()}`,
      );
    } catch (error) {
      return res.redirect(
        '/dashboard/devices/new?status=' +
          encodeURIComponent('Failed to create device'),
      );
    }
  }

  @UseGuards(DashboardAuthGuard)
  @Get('/dashboard/devices/:id')
  async showDevice(
    @Param('id') id: string,
    @Query('status') status: string | undefined,
    @Query('token') token: string | undefined,
    @Query('showQr') showQr: string | undefined,
    @Res() res: Response,
  ) {
    const device = await this.devicesService.getDeviceOrThrow(id);
    const commands = await this.commandsService.listCommands(id);
    const latestHeartbeat = await this.devicesService.getLatestHeartbeat(id);
    const provisioning = {
      portal_url: process.env.PORTAL_URL ?? '',
      device_id: device.id,
      device_token: token ?? 'Rotate token to view a fresh value.',
      allowed_package: device.allowedPackage,
      initial_pin: device.initialPinPlaintext ?? '1234', // Use stored PIN or default
    };

    return res.render('devices/detail', {
      title: device.displayName,
      device,
      commands,
      latestHeartbeat,
      status,
      token,
      provisioning,
      qr:
        showQr !== undefined
          ? await generateProvisioningQr(provisioning)
          : undefined,
    });
  }

  @UseGuards(DashboardAuthGuard)
  @Post('/dashboard/devices/:id/commands/pin')
  async queuePinUpdate(
    @Param('id') id: string,
    @Body('pin') pin: string,
    @Res() res: Response,
  ) {
    if (!pin || pin.length < 4) {
      return res.redirect(
        `/dashboard/devices/${id}?status=${encodeURIComponent(
          'PIN must be at least 4 digits',
        )}`,
      );
    }
    const updatedDevice = await this.devicesService.rotatePin(id, pin);
    await this.commandsService.queueCommand(id, CommandType.PIN_UPDATE, {
      pin_hash: updatedDevice.pinHash,
      pin_salt: updatedDevice.pinSalt,
    });
    return res.redirect(
      `/dashboard/devices/${id}?status=${encodeURIComponent(
        'PIN update queued',
      )}`,
    );
  }

  @UseGuards(DashboardAuthGuard)
  @Post('/dashboard/devices/:id/commands/package')
  async queuePackageUpdate(
    @Param('id') id: string,
    @Body('allowedPackage') allowedPackage: string,
    @Res() res: Response,
  ) {
    if (!allowedPackage) {
      return res.redirect(
        `/dashboard/devices/${id}?status=${encodeURIComponent(
          'Package name is required',
        )}`,
      );
    }
    await this.devicesService.updateDevice(id, { allowedPackage });
    await this.commandsService.queueCommand(id, CommandType.PACKAGE_UPDATE, {
      allowed_package: allowedPackage,
    });
    return res.redirect(
      `/dashboard/devices/${id}?status=${encodeURIComponent(
        'Package update queued',
      )}`,
    );
  }

  @UseGuards(DashboardAuthGuard)
  @Post('/dashboard/devices/:id/commands/reboot')
  async queueReboot(@Param('id') id: string, @Res() res: Response) {
    await this.commandsService.queueCommand(id, CommandType.REBOOT);
    return res.redirect(
      `/dashboard/devices/${id}?status=${encodeURIComponent(
        'Reboot command queued',
      )}`,
    );
  }

  @UseGuards(DashboardAuthGuard)
  @Post('/dashboard/devices/:id/token')
  async rotateToken(
    @Param('id') id: string,
    @Res() res: Response,
  ) {
    const result = await this.devicesService.rotateDeviceToken(id);
    const message = encodeURIComponent('New device token generated');
    const token = encodeURIComponent(result.token);
    return res.redirect(
      `/dashboard/devices/${id}?status=${message}&token=${token}`,
    );
  }

  private async hasValidSession(req: Request): Promise<boolean> {
    const token: string | undefined =
      req.cookies?.[SESSION_COOKIE] || req.signedCookies?.[SESSION_COOKIE];
    if (!token) {
      return false;
    }
    try {
      await this.jwtService.verifyAsync(token);
      return true;
    } catch {
      return false;
    }
  }
}

