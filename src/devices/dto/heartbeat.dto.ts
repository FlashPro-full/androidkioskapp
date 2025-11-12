import { IsNumber, IsOptional, IsString, Max, Min } from 'class-validator';

export class HeartbeatDto {
  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  batteryLevel?: number;

  @IsOptional()
  @IsString()
  wifiSsid?: string;

  @IsOptional()
  @IsString()
  deviceSerial?: string;

  @IsOptional()
  @IsString()
  notes?: string;
}



