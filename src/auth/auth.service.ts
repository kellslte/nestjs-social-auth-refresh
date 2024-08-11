import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as argon from 'argon2';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from 'src/users/schema/user.schema';
import { Response } from 'express';
import { TokenPayload } from 'src/lib/types';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    try {
      const user = await this.userService.fetchUserRecord({ email });

      if (!(await argon.verify(user.password, password)))
        throw new UnauthorizedException('Invalid credentials');

      // remove the user password first before returning the user
      delete user.password;

      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async verifyRefreshToken(refreshToken: string, userId: string): Promise<User> {
      try {
        const user = await this.userService.fetchUserRecord({ _id: userId });

        if(!(await argon.verify(user.refreshToken, refreshToken))) {
          throw new UnauthorizedException('Invalid refresh token');
        }

        delete user.password;

        return user;
      } catch (error) {
        throw new UnauthorizedException('Invalid refresh token');
      }
   }

  async authenticateUser(user: User, res: Response) {
    // set the access token expiry time in milliseconds
    const expiryTime = new Date();
    expiryTime.setMilliseconds(
      expiryTime.getTime() +
        parseInt(
          this.configService.getOrThrow<string>('JWT_EXPIRATION_TIME_MS'),
        ),
    );

    const refreshTokenExpiryTime = new Date();
    refreshTokenExpiryTime.setMilliseconds(
      refreshTokenExpiryTime.getTime() +
        parseInt(
          this.configService.getOrThrow<string>(
            'JWT_REFRESH_TOKEN_EXPIRATION_TIME_MS',
          ),
        ),
    );

    //create a payload for the jwt token
    const payload: TokenPayload = {
      sub: user._id.toHexString(),
      email: user.email,
    };

    // sign the jwt token
    const token = this.jwtService.sign(payload, {
      secret: this.configService.getOrThrow<string>('JWT_SECRET'),
      expiresIn: `${this.configService.getOrThrow<string>('JWT_EXPIRATION_TIME_MS')}ms`,
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.getOrThrow<string>('JWT_SECRET_REFRESH'),
      expiresIn: `${this.configService.getOrThrow<string>('JWT_REFRESH_TOKEN_EXPIRATION_TIME_MS')}ms`,
    });

    // update the user record witht the refresh token
    await this.userService.updateUser(
      {
        _id: user._id,
      },
      {
        $set: {
          refreshToken,
        },
      },
    );

    // set the response cookie
    res.cookie('Authentication', token, {
      expires: expiryTime,
      httpOnly: true,
      secure:
        this.configService.getOrThrow<string>('NODE_ENV') === 'production',
      sameSite: 'none',
    });

    res.cookie('Refresh', refreshToken, {
      expires: refreshTokenExpiryTime,
      httpOnly: true,
      secure:
        this.configService.getOrThrow<string>('NODE_ENV') === 'production',
      sameSite: 'none',
    });
  }
}
