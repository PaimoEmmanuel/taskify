import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import * as crypto from 'crypto';
import { ResetPassworDto } from './dto/reset-password.dto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signup(authDto: AuthDto) {
    const { email, password } = authDto;
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new BadRequestException('User with this email already exist!');
    }

    const hashedPassword = await this.hashPassword(password);

    const user = await this.prisma.user.create({
      data: { email, password: hashedPassword },
    });
    return {
      message: 'signup successful',
      user: {
        id: user.id,
        email: user.email,
        createdAt: user.createdAt,
      },
    };
  }

  async signin(authDto: AuthDto, res: Response) {
    const { email, password } = authDto;
    const user = await this.prisma.user.findUnique({
      where: { email },
    });
    if (!user) {
      throw new BadRequestException('Invalid email or password');
    }
    const passwordMatch = await this.passwordMatch(password, user.password);

    if (!passwordMatch) {
      throw new BadRequestException('Invalid email or password');
    }
    // JWT Signin
    const token = await this.signToken({ id: user.id, email });
    if (!token) {
      throw new ForbiddenException();
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    res.cookie('token', token);
    res.send({ message: 'signin successful', token });
  }

  async signout(res: Response) {
    res.clearCookie('token');
    res.send({ message: 'Sign out successful' });
  }

  async forgotPassword(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new BadRequestException('User not found');

    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 1000 * 60 * 15); // 15 mins

    await this.prisma.user.update({
      where: { email },
      data: {
        passwordResetToken: token,
        passwordResetExpires: expires,
      },
    });

    // Send email with reset link
    /*
    const resetLink = `https://yourapp.com/reset-password?token=${token}`;
    await this.mailer.sendMail({
      to: user.email,
      subject: 'Reset Your Password',
      html: `Click <a href="${resetLink}">here</a> to reset your password`,
    });
    */

    return { message: 'Reset email sent' };
  }

  async resetPassword(resetPassworDto: ResetPassworDto) {
    const { email, token, newPassword } = resetPassworDto;
    const user = await this.prisma.user.findFirst({
      where: {
        email,
        passwordResetToken: token,
        passwordResetExpires: { gte: new Date() },
      },
    });
    if (!user) {
      throw new NotFoundException('Invalid or expired token');
    }
    const hashedPassword = await this.hashPassword(newPassword);
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        passwordResetToken: null,
        passwordResetExpires: null,
      },
    });

    return { message: 'Password reset successful' };
  }

  async passwordMatch(password: string, userPassword: string) {
    return await bcrypt.compare(password, userPassword);
  }

  async hashPassword(password: string) {
    const HASH_ROUNDS = 10;
    return await bcrypt.hash(password, HASH_ROUNDS);
  }

  private async signToken(payload: { id: string; email: string }) {
    return this.jwtService.signAsync(payload);
  }
}
