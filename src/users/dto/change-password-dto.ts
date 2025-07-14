import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';
import { Match } from 'src/validators/match';
import { PasswordMismatch } from 'src/validators/password-mismatch';

export class ChangePasswordDto {
  @IsNotEmpty()
  @IsString()
  @Length(3, 20, {
    message:
      'Password must be between $constraint1 and $constraint2 characters',
  })
  currentPassword: string;

  @IsString()
  @Matches(/(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+/, {
    message:
      'Password must contain uppercase, lowercase, number, and special character',
  })
  @PasswordMismatch()
  newPassword: string;

  @Match('newPassword', { message: 'Passwords do not match' })
  confirmPassword: string;
}
