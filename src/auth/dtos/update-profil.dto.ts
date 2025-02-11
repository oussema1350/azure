import { IsOptional, IsString, MinLength, Matches } from 'class-validator';

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MinLength(3, { message: 'Name must be at least 3 characters long' })
  name?: string;

  @IsOptional()
  @IsString()
  oldPassword?: string;

  @IsOptional()
  @IsString()
  @MinLength(6, { message: 'Password must be at least 6 characters long' })
  @Matches(/^(?=.*[0-9])/, {
    message: 'Password must contain at least one number',
  })
  newPassword?: string;
}
