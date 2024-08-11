import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { TokenPayload } from 'src/lib/types';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtRefreshTrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private readonly configService: ConfigService, private readonly authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (req: Request) => req.cookies?.Authentication,
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.getOrThrow('JWT_SECRET_REFRESH'),
      passRequestToCallback: true,
    });
  }

  async validate(request: Request, payload: TokenPayload) {
    return this.authService.verifyRefreshToken(request.cookies?.Refresh, payload.sub);
  }
}
