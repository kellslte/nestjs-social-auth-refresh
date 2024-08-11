import { Controller, Post, Res, UseGuards } from '@nestjs/common';
import { LocalAuthGuard } from './guards/local.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { User } from 'src/users/schema/user.schema';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { JwtRefreshAuthGuard } from './guards/jwt-refresh.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @UseGuards(LocalAuthGuard)
  async login(@CurrentUser() user: User, @Res({ passthrough: true }) res: Response) {
    await this.authService.authenticateUser(user, res);
  }
    
    @Post('refresh')
    @UseGuards(JwtRefreshAuthGuard)
    async refreshJwtToken(@CurrentUser() user: User, @Res({ passthrough: true }) res: Response) {
        await this.authService.authenticateUser(user, res);
     }
}
