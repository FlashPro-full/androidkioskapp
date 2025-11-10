import {
  Body,
  Controller,
  Get,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from '../auth/auth.service';
import { DevicesService } from '../devices/devices.service';
import { CommandsService } from '../commands/commands.service';
import { DashboardAuthGuard } from './dashboard-auth.guard';
import { CommandType } from '../commands/entities/command.entity';
import { JwtService } from '@nestjs/jwt';

const SESSION_COOKIE = 'session_token';

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
    if (await this.hasValidSession(req)) {
      return res.redirect('/dashboard/devices');
    }
    return res.render('auth/login', { title: 'Login' });
  }

  @Post('/dashboard/login')
  async handleLogin(
    @Body('username') username: string,
    @Body('password') password: string,
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
      return res.redirect('/dashboard/devices');
    } catch (error) {
      return res.render('auth/login', {
        title: 'Login',
        error: 'Invalid credentials',
        username,
      });
    }
  }

  @Get('/dashboard/logout')
  async logout(@Res() res: Response) {
    res.clearCookie(SESSION_COOKIE);
    return res.redirect('/dashboard/login');
  }

  @UseGuards(DashboardAuthGuard)
  @Get('/dashboard/devices')
  async listDevices(
    @Query('status') status: string | undefined,
    @Res() res: Response,
  ) {
    const devices = await this.devicesService.findAll();
    return res.render('devices/list', {
      title: 'Devices',
      devices,
      status,
    });
  }

  @UseGuards(DashboardAuthGuard)
  @Get('/dashboard/devices/:id')
  async showDevice(
    @Param('id') id: string,
    @Query('status') status: string | undefined,
    @Query('token') token: string | undefined,
    @Res() res: Response,
  ) {
    const device = await this.devicesService.getDeviceOrThrow(id);
    const commands = await this.commandsService.listCommands(id);
    const provisioning = {
      portal_url: process.env.PORTAL_URL ?? '',
      device_id: device.id,
      device_token: token ?? 'Rotate token to view a fresh value.',
      allowed_package: device.allowedPackage,
      initial_pin: 'Use PIN command to rotate',
    };

    return res.render('devices/detail', {
      title: device.displayName,
      device,
      commands,
      status,
      token,
      provisioning,
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

