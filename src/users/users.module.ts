import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { JwtStrategy } from 'src/auth/jwt.strategy';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [UsersController],
  providers: [UsersService, JwtStrategy],
})
export class UsersModule {}
