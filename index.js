import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import cors from 'cors';
import { signup, login, forgotPassword, resetPassword, checkResetToken} from './routes/authRoutes.js';

dotenv.config();
const app = express();
const PORT = process.env.PORT ;

app.use(express.json());
app.use(cors());

mongoose.connect('mongodb+srv://sivaprabhakaran94:Siva153@cluster0.zl5zlfx.mongodb.net/', {
 
});

// Use the individual exported functions from authRoutes
app.post('/api/signup', signup);
app.post('/api/login', login);
app.post('/api/forgot-password', forgotPassword);
app.post('/api/reset-password/', resetPassword);

app.get('/api/check-reset-token/:token', checkResetToken);
app.listen(PORT, () => 
  console.log(`Server is running on port ${PORT}`));

