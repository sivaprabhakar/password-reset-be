
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const User = require('../models/User');
const verifyToken = require('../verifyToken');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// Signup
router.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
    });

    await user.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error signing up:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Forgot Password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const token = crypto.randomBytes(20).toString('hex');
    const tokenExpiration = Date.now() + 3600000; // 1 hour

    await User.findByIdAndUpdate(user._id, { resetPasswordToken: token, resetPasswordExpires: tokenExpiration });

    const resetLink = `http://localhost:8000/reset-password/${token}`;
    const mailOptions = {
      from: process.env.EMAIL_USERNAME,
      to: user.email,
      subject: 'Password Reset',
      html: `<p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
            <p>Please click on the following link to reset your password:</p>
            <p><a href="${resetLink}">${resetLink}</a></p>
            <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>`,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({ message: 'Password reset email sent. Please check your inbox.' });
  } catch (error) {
    console.error('Error sending forgot password request:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
  try {
    const { password } = req.body;
    const { authorization } = req.headers;

    const decodedToken = jwt.verify(authorization, process.env.SECRET_KEY);

    const user = await User.findOne({
      _id: decodedToken.id,
      resetPasswordToken: authorization,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

module.exports = router;
