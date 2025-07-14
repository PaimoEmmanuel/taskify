import { IsNotEmpty, IsString, IsUrl } from 'class-validator';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  @IsUrl()
  avatarUrl: string;
}
