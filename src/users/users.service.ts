import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { FilterQuery, Model } from 'mongoose';
import { User } from './schema/user.schema';
import { CreateUserRequest } from './dto/createUserRequest';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async createUser(body: CreateUserRequest): Promise<User> {
    return (await this.userModel.create(body)).save();
  }

  async fetchUserRecord(query: FilterQuery<User>): Promise<User> {
    const user = (await this.userModel.findOne(query)).toObject();

    if (!user) throw new NotFoundException('User not found');

    return user;
  }

  async fetchUsers(): Promise<Partial<User>[]> {
    const users = await this.userModel.find({}).exec();
    // remove the password field from the user object before returning it
    return users.map((user) => {
      const { password, ...userWithoutPassword } = user.toObject();
      return userWithoutPassword as Partial<User>;
    });
  }

  async updateUser(query: FilterQuery<User>, body: any): Promise<User> {
    return await this.userModel.findOneAndUpdate(query, body, { new: true }).exec();
  }
}
