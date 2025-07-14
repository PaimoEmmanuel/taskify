import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  @Length(3, 20, {
    message:
      'Password must be between $constraint1 and $constraint2 characters',
  })
  //   @Matches(/(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+/, {
  //     message:
  //       'Password must contain uppercase, lowercase, number, and special character',
  //   })
  password: string;
}
