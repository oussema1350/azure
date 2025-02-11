import { IsString, Matches, MinLength } from 'class-validator';

export class ResetPasswordDto {
  resetToken: string;
}

