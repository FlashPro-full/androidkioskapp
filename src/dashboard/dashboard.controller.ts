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
import { join, resolve } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { FileInterceptor } from '@nestjs/platform-express';
import { UseInterceptors, UploadedFile } from '@nestjs/common';
import { diskStorage } from 'multer';
import { AuthService } from '../auth/auth.service';
import { DevicesService } from '../devices/devices.service';
import { CommandsService } from '../commands/commands.service';
import { DashboardAuthGuard } from './dashboard-auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';
import { UserRole } from '../users/entities/user.entity';
import { CommandType } from '../commands/entities/command.entity';
import { JwtService } from '@nestjs/jwt';
import { DashboardUnauthorizedFilter } from './dashboard-unauthorized.filter';
import { CreateDeviceDto } from '../devices/dto/create-device.dto';
import { generateProvisioningQr } from './provisioning-qr';
import { UsersService } from '../users/users.service';
import { ConfigService } from '@nestjs/config';

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
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
  ) {}

  @Get('/')
  async root(@Res() res: Response) {
    return res.redirect('/dashboard/devices');
  }

  @UseGuards(DashboardAuthGuard)
  @Get('/dashboard/download/apk')
  async downloadApk(@Res() res: Response) {
    // Try multiple possible APK locations (prioritize uploaded APK)
    const possiblePaths = [
      // Uploaded APK (highest priority)
      join(process.cwd(), 'public', 'uploads', 'kiosk-launcher.apk'),
      // Relative to portal directory
      join(process.cwd(), '..', 'app', 'build', 'outputs', 'apk', 'release', 'app-release.apk'),
      join(process.cwd(), '..', 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk'),
      // In public directory
      join(process.cwd(), 'public', 'kiosk.apk'),
      join(process.cwd(), 'public', 'app-release.apk'),
      // Environment variable path
      process.env.APK_PATH,
    ].filter(Boolean) as string[];

    let apkPath: string | null = null;
    for (const path of possiblePaths) {
      if (path && existsSync(path)) {
        apkPath = path;
        break;
      }
    }

    if (!apkPath) {
      return res.status(404).send('APK file not found. Please ensure the APK is built and placed in the public directory or set APK_PATH environment variable.');
    }

    const fileName = 'kiosk-launcher.apk';
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    return res.sendFile(resolve(apkPath));
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('/dashboard/upload/apk')
  @UseInterceptors(
    FileInterceptor('apk', {
      storage: diskStorage({
        destination: (req, file, cb) => {
          const uploadDir = join(process.cwd(), 'public', 'uploads');
          if (!existsSync(uploadDir)) {
            mkdirSync(uploadDir, { recursive: true });
          }
          cb(null, uploadDir);
        },
        filename: (req, file, cb) => {
          // Always save as kiosk-launcher.apk (replace existing)
          cb(null, 'kiosk-launcher.apk');
        },
      }),
      limits: {
        fileSize: 100 * 1024 * 1024, // 100MB max
      },
      fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/vnd.android.package-archive' || file.originalname.endsWith('.apk')) {
          cb(null, true);
        } else {
          cb(new Error('Only APK files are allowed'), false);
        }
      },
    }),
  )
  async uploadApk(
    @UploadedFile() file: Express.Multer.File,
    @Res() res: Response,
  ) {
    if (!file) {
      return res.status(400).send('No file uploaded');
    }

    return res.redirect('/dashboard/devices?status=APK uploaded successfully');
  }

  @Get('/dashboard/register')
  async showRegister(
    @Query('status') status: string | undefined,
    @Res() res: Response,
  ) {
    return res.render('auth/register', {
      title: 'Register',
      status,
    });
  }

  @Post('/dashboard/register')
  async handleRegister(
    @Body('username') username: string,
    @Body('password') password: string,
    @Res() res: Response,
  ) {
    const trimmedUsername = username?.trim();
    if (!trimmedUsername || trimmedUsername.length < 3) {
      return res.render('auth/register', {
        title: 'Register',
        error: 'Username must be at least 3 characters',
        username: trimmedUsername,
      });
    }

    if (!password || password.length < 8) {
      return res.render('auth/register', {
        title: 'Register',
        error: 'Password must be at least 8 characters',
        username: trimmedUsername,
      });
    }

    try {
      await this.usersService.create(
        trimmedUsername,
        password,
        undefined, // Default to VIEWER
        undefined, // Default to PENDING
      );
      return res.redirect(
        '/dashboard/login?message=' +
          encodeURIComponent(
            'Registration successful! Your account is pending approval. Please contact an administrator.',
          ),
      );
    } catch (error: any) {
      return res.render('auth/register', {
        title: 'Register',
        error: error.message || 'Registration failed',
        username: trimmedUsername,
      });
    }
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
    } catch (error: any) {
      const errorMessage = error.message || 'Invalid credentials';
      return res.render('auth/login', {
        title: 'Login',
        error: errorMessage,
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
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const devices = await this.devicesService.findAll();
    return res.render('devices/list', {
      title: 'Devices',
      devices,
      status,
      message,
      user: (req as any).user,
    });
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.TECHNICIAN)
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

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('/dashboard/devices/new')
  async showCreateDevice(
    @Query('status') status: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    return res.render('devices/new', {
      title: 'Register Device',
      status,
      user: (req as any).user,
      defaults: {
        allowedPackage:
          process.env.DEFAULT_ALLOWED_PACKAGE ?? 'com.client.businessapp',
      },
    });
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('/dashboard/devices/new')
  async createDevice(
    @Body('displayName') displayName: string,
    @Body('allowedPackage') allowedPackage: string | undefined,
    @Body('initialPin') initialPin: string | undefined,
    @Body('expectedDeviceSerial') expectedDeviceSerial: string | undefined,
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
      expectedDeviceSerial: expectedDeviceSerial?.trim() || undefined,
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
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const device = await this.devicesService.getDeviceOrThrow(id);
    const commands = await this.commandsService.listCommands(id);
    const latestHeartbeat = await this.devicesService.getLatestHeartbeat(id);
    const user = (req as any).user;
    const userRole = user?.role;
    
    // Only ADMIN and TECHNICIAN can view QR codes and sensitive provisioning data
    const canViewQr = userRole === UserRole.ADMIN || userRole === UserRole.TECHNICIAN;
    
    const provisioning = {
      portal_url: process.env.PORTAL_URL ?? '',
      device_id: device.id,
      device_token: canViewQr 
        ? (token ?? 'Rotate token to view a fresh value.')
        : 'Access restricted',
      allowed_package: device.allowedPackage,
      initial_pin: canViewQr 
        ? (device.initialPinPlaintext ?? '1234')
        : 'Access restricted',
      expected_device_serial: device.expectedDeviceSerial,
    };

    return res.render('devices/detail', {
      title: device.displayName,
      device,
      commands,
      latestHeartbeat,
      status,
      token,
      provisioning,
      user,
      canViewQr,
      qr:
        showQr !== undefined && canViewQr
          ? await generateProvisioningQr(provisioning)
          : undefined,
    });
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.TECHNICIAN)
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

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.TECHNICIAN)
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

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN, UserRole.TECHNICIAN)
  @Post('/dashboard/devices/:id/commands/reboot')
  async queueReboot(@Param('id') id: string, @Res() res: Response) {
    await this.commandsService.queueCommand(id, CommandType.REBOOT);
    return res.redirect(
      `/dashboard/devices/${id}?status=${encodeURIComponent(
        'Reboot command queued',
      )}`,
    );
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
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

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('/dashboard/devices/:id/expected-serial')
  async updateExpectedSerial(
    @Param('id') id: string,
    @Body('expectedDeviceSerial') expectedDeviceSerial: string | undefined,
    @Res() res: Response,
  ) {
    await this.devicesService.updateDevice(id, {
      expectedDeviceSerial: expectedDeviceSerial?.trim() || undefined,
    });
    return res.redirect(
      `/dashboard/devices/${id}?status=${encodeURIComponent(
        'Expected device serial updated',
      )}`,
    );
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('/dashboard/users')
  async listUsers(
    @Query('status') status: string | undefined,
    @Query('message') message: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const users = await this.usersService.findAll();
    // Get the initial admin username to exclude from pending list
    const initialAdminUsername =
      this.configService.get<string>('ADMIN_USERNAME') ?? 'paulkiosk123';
    
    // Separate pending and active users for the view
    // Exclude the initial admin from pending users (it's already active)
    const pendingUsers = users.filter(
      (u) => u.status === 'PENDING' && u.username !== initialAdminUsername,
    );
    const activeUsers = users.filter((u) => u.status === 'ACTIVE');
    return res.render('users/list', {
      title: 'Users',
      users,
      pendingUsers,
      activeUsers,
      status,
      message,
      user: (req as any).user,
    });
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Get('/dashboard/users/new')
  async showCreateUser(
    @Query('status') status: string | undefined,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    return res.render('users/new', {
      title: 'Create User',
      status,
      user: (req as any).user,
    });
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('/dashboard/users/new')
  async createUser(
    @Body('username') username: string,
    @Body('password') password: string,
    @Body('role') role: string,
    @Res() res: Response,
  ) {
    const trimmedUsername = username?.trim();
    if (!trimmedUsername || trimmedUsername.length < 3) {
      return res.redirect(
        '/dashboard/users/new?status=' +
          encodeURIComponent('Username must be at least 3 characters'),
      );
    }

    if (!password || password.length < 8) {
      return res.redirect(
        '/dashboard/users/new?status=' +
          encodeURIComponent('Password must be at least 8 characters'),
      );
    }

    if (!role || !Object.values(UserRole).includes(role as UserRole)) {
      return res.redirect(
        '/dashboard/users/new?status=' +
          encodeURIComponent('Invalid role selected'),
      );
    }

    try {
      await this.usersService.create(
        trimmedUsername,
        password,
        role as UserRole,
      );
      return res.redirect(
        '/dashboard/users?status=' + encodeURIComponent('User created'),
      );
    } catch (error: any) {
      return res.redirect(
        '/dashboard/users/new?status=' +
          encodeURIComponent(error.message || 'Failed to create user'),
      );
    }
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('/dashboard/users/:id/delete')
  async deleteUser(@Param('id') id: string, @Res() res: Response) {
    try {
      await this.usersService.delete(id);
      return res.redirect(
        '/dashboard/users?status=' + encodeURIComponent('User deleted'),
      );
    } catch (error: any) {
      return res.redirect(
        '/dashboard/users?status=' +
          encodeURIComponent(error.message || 'Failed to delete user'),
      );
    }
  }

  @UseGuards(DashboardAuthGuard, RolesGuard)
  @Roles(UserRole.ADMIN)
  @Post('/dashboard/users/:id/update')
  async updateUser(
    @Param('id') id: string,
    @Body('role') role: string | undefined,
    @Body('password') password: string | undefined,
    @Res() res: Response,
  ) {
    try {
      const updates: { role?: UserRole; password?: string } = {};
      if (role && Object.values(UserRole).includes(role as UserRole)) {
        updates.role = role as UserRole;
      }
      if (password && password.length >= 8) {
        updates.password = password;
      }
      await this.usersService.update(id, updates);
      return res.redirect(
        '/dashboard/users?status=' + encodeURIComponent('User updated'),
      );
    } catch (error: any) {
      return res.redirect(
        '/dashboard/users?status=' +
          encodeURIComponent(error.message || 'Failed to update user'),
      );
    }
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

