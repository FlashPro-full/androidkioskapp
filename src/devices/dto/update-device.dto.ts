import { IsOptional, IsString, MinLength } from 'class-validator';

export class UpdateDeviceDto {
  @IsString()
  @IsOptional()
  @MinLength(2)
  displayName?: string;

  @IsString()
  @IsOptional()
  allowedPackage?: string;

  @IsString()
  @IsOptional()
  expectedDeviceSerial?: string;
}



