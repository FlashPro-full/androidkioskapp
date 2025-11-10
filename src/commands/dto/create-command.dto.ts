import { IsEnum, IsOptional, IsString } from 'class-validator';
import { CommandType } from '../entities/command.entity';

export class CreateCommandDto {
  @IsEnum(CommandType)
  type: CommandType;

  @IsOptional()
  @IsString()
  pin?: string;

  @IsOptional()
  @IsString()
  allowedPackage?: string;
}



