import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  Matches,
} from 'class-validator';

export class ResetPassworDto {
  @IsEmail()
  email: string;

  @IsString()
  token: string;

  @IsNotEmpty()
  @IsString()
  @Length(3, 20, {
    message:
      'Password must be between $constraint1 and $constraint2 characters',
  })
  @Matches(/(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+/, {
    message:
      'Password must contain uppercase, lowercase, number, and special character',
  })
  newPassword: string;
}
