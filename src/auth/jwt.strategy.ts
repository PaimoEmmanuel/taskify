import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    const jwtSecret = configService.get<string>('JWT_SECRET');

    super({
      jwtFromRequest: JwtStrategy.extractJWT,
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  private static extractJWT(req: Request) {
    if (req.cookies && req.cookies.token) {
      return req.cookies.token;
    }
    return ExtractJwt.fromAuthHeaderAsBearerToken()(req);
  }

  async validate(payload: any) {
    return { id: payload.id, email: payload.email };
  }
}
