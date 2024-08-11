import { Body, Controller, Get, Post, Res, UseGuards } from '@nestjs/common';
import { CreateUserRequest } from './dto/createUserRequest';
import { UsersService } from './users.service';
import { JwtAuthGuard } from 'src/auth/guards/jwt.guard';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { User } from './schema/user.schema';

@Controller('users')
export class UsersController {
  constructor(private readonly userService: UsersService) {}

  @Post()
  async createUser(@Body() body: CreateUserRequest, @Res() res) {
    const user = await this.userService.createUser(body);

    return res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        user,
      },
    });
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  async getUsers(@CurrentUser() user: User, @Res() res) {
    const users = (await this.userService.fetchUsers()).map((user) => {
      const { password, ...userWithoutPassword } = user;
      return userWithoutPassword
    });

    return res.status(200).json({
      success: true,
      message: 'Users fetched successfully',
      data: {
        users,
      },
    });
  }
}
