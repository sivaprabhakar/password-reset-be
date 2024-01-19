
import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name:{type:String,
    required:[true,"Name is required"]},
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

const User = mongoose.model('User', userSchema);

export default User;
