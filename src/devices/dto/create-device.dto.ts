import { IsOptional, IsString, MinLength } from 'class-validator';

export class CreateDeviceDto {
  @IsString()
  @MinLength(2)
  displayName: string;

  @IsString()
  @IsOptional()
  allowedPackage?: string;

  @IsString()
  @IsOptional()
  @MinLength(4)
  initialPin?: string;
}



