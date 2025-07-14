import { Body, Controller, Get, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { ResetPassworDto } from './dto/reset-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() authDto: AuthDto) {
    return this.authService.signup(authDto);
  }

  @Post('signin')
  signin(@Body() authDto: AuthDto, @Res() res) {
    return this.authService.signin(authDto, res);
  }

  @Get('signout')
  signout(@Res() res) {
    return this.authService.signout(res);
  }

  @Post('forgot-password')
  forgotPassword(@Body() body: { email: string }) {
    return this.authService.forgotPassword(body.email);
  }

  @Post('reset-password')
  resetPassword(@Body() resetPassworDto: ResetPassworDto) {
    return this.authService.resetPassword(resetPassworDto);
  }
}
