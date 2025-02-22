import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from "crypto";
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import mongoose from 'mongoose'; // Import mongoose

const app = express();
app.use(bodyParser.json());
dotenv.config(); // Load environment variables

// Configure CORS options
const corsOptions = {
  origin: ['https://flag-folio.vercel.app', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

// Define User schema and model
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  email: { type: String, unique: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

const User = mongoose.model('User', userSchema);

// Sign-up route
app.post('/signup', async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ message: 'Username, password and email required' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hash, email });
    await newUser.save();
    res.status(201).json({ id: newUser._id, username });
  } catch (err) {
    if (err.code === 11000) { // Duplicate key error
      return res.status(400).json({ message: "User already exists" });
    }
    res.status(500).json({ message: "Database error" });
  }
});

// Sign-in route
app.post('/signin', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Database error" });
  }
});

// Forgot Password Route
app.post('/forgotPassword', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json('Email does not exist');

    const token = crypto.randomBytes(32).toString('hex');
    const expirationTime = new Date(Date.now() + 3600000); // Token valid for 1 hour

    user.resetPasswordToken = token;
    user.resetPasswordExpires = expirationTime;
    await user.save();

    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      to: user.email,
      subject: 'Password Reset',
      text: `You are receiving this because you have requested to reset your password.\n\n` +
            `Please click on the following link or paste it into your browser to complete the process:\n\n` +
            `http://flag-folio.vercel.app/resetPassword?token=${token}&email=${encodeURIComponent(user.email)}\n\n` +
            `If you did not request this, please ignore this email.\n`,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json('Password reset link sent.');
    
  } catch (err) {
    console.error('Error:', err);
    res.status(500).json('Error sending password reset email.');
  }
});

// Reset Password Route
app.post('/resetPassword', async (req, res) => {
  const { token, email, newPassword } = req.body;

  try {
    const user = await User.findOne({
      email,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) return res.status(400).send('Invalid or expired token');

    const hash = await bcrypt.hash(newPassword, 10);
    
    user.password = hash;
    user.resetPasswordToken = undefined; // Clear token
    user.resetPasswordExpires = undefined; // Clear expiration time
    await user.save();

    res.status(200).send('Password has been successfully updated.');
    
  } catch (err) {
    res.status(500).send('Error updating password.');
  }
});

// Middleware to authenticate JSON Web Tokens
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
}

// Protected route example for authenticated users only
app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    message: 'This is a protected route',
    userId: req.user.id,
  });
});

// Server listening on specified port
const port = process.env.PORT || 5000;
app.listen(port, () => console.log("Server running on port:", port));
