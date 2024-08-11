import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { SchemaTypes, Types } from 'mongoose';
import * as argon from 'argon2';

@Schema({ timestamps: true })
export class User {
  @Prop({ type: SchemaTypes.ObjectId, auto: true })
  _id: Types.ObjectId;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ default: null })
  refreshToken?: string;
}

const UserSchema = SchemaFactory.createForClass(User);

// a middleware to hard the password before it is saved
UserSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await argon.hash(this.password);
  }

  if (this.isModified('refreshToken')) {
    this.refreshToken = await argon.hash(this.refreshToken);
   }
  next();
});

export { UserSchema };
