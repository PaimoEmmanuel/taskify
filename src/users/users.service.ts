import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { ChangePasswordDto } from './dto/change-password-dto';
import { AuthService } from 'src/auth/auth.service';

@Injectable()
export class UsersService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly authService: AuthService,
  ) {}

  async findById(id: string) {
    const user = await this.prismaService.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async getProfile(id: string) {
    const user = await this.findById(id);
    delete user.password;
    return user;
  }

  async updateProfile(id: string, updateUserDto: UpdateUserDto) {
    const user = await this.prismaService.user.update({
      where: { id },
      data: { ...updateUserDto },
    });
    delete user.password;
    return user;
  }

  async changePassword(id: string, changePasswordDto: ChangePasswordDto) {
    const { currentPassword, newPassword } = changePasswordDto;
    const user = await this.findById(id);

    if (!user) {
      throw new NotFoundException('User not found');
    }
    const passwordMatch = this.authService.passwordMatch(
      currentPassword,
      user.password,
    );
    if (!passwordMatch) {
      throw new UnauthorizedException('Incorrect password!');
    }
    const hashedPassword = await this.authService.hashPassword(newPassword);
    await this.prismaService.user.update({
      where: { id },
      data: { password: hashedPassword },
    });
    return { message: 'Password changed successfully' };
  }
}
