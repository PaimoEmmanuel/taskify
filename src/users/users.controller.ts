import { Controller, Get, Body, Patch, UseGuards, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from 'src/auth/jwt.guard';
import { ChangePasswordDto } from './dto/change-password-dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Req() req) {
    return this.usersService.findById(req.user.id);
  }

  @Patch('profile')
  async updateProfile(@Req() req, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.updateProfile(req.user.id, updateUserDto);
  }

  @Patch('change-password')
  async changePassword(
    @Req() req,
    @Body() changePasswordDto: ChangePasswordDto,
  ) {
    return this.usersService.changePassword(req.user.id, changePasswordDto);
  }
}
