import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mysql from 'mysql2';
import crypto from "crypto";
import nodemailer from 'nodemailer'
import dotenv from 'dotenv'

const app = express();
app.use(bodyParser.json());
// Load environment variables from .env file
dotenv.config(); // Call config to load variables

// Configure CORS options
const corsOptions = {
  origin: ['https://flag-folio.vercel.app', 'http://localhost:5173'],  // Allow this origin
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Allowed methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allowed headers
};

// Use CORS middleware with options
app.use(cors(corsOptions));

// Create MySQL connection pool
const db = mysql.createConnection({
  host: 'my-mysql', // Change this if you're using Docker
  user: 'root', // MySQL username
  password: '3353', // MySQL password (set this according to your configuration)
  database: 'flagfolio_data', // Database name
});

// Connect to the database
db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL');
  // Create users table if it doesn't exist (MySQL syntax)
db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    password VARCHAR(255),
    email VARCHAR(255) UNIQUE,
    resetPasswordToken VARCHAR(255),  
    resetPasswordExpires DATETIME      
  )
`, (err) => {
  if (err) {
    console.log("Error creating table: " + err.message);
  }
});
});





// Sign-up route
app.post('/signup', (req, res) => {
  const { username, password, email } = req.body;

  // Check for missing fields
  if (!username || !password || !email) {
    return res.status(400).json({ message: 'Username, password and email required' });
  }

  // Hash the password with bcrypt
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ message: 'Error hashing password' });

    // Insert new user into the database
    db.query("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", [username, hash, email], (err, results) => {
      if (err) {
        // Check for duplicate username error
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: "User already exists" });
        }
        return res.status(500).json({ message: "Database error" });
      }
      res.status(201).json({ id: results.insertId, username });
    });
  });
});


// Sign-in route
app.post('/signin', (req, res) => {
  const { username, password } = req.body;

  // Check for missing fields
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  // Fetch user from the database by username
  db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'User not found' });

    const user = results[0]; // Get the first user from results

    // Compare input password with hashed password
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) return res.status(401).json({ message: "Invalid password" });

      // Token creation
      const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: '1h' }); // Replace with your JWT secret

      res.json({ token });
    });
  });
});


// Forgot Password Route
app.post('/forgotPassword', async (req, res) => {
  const { email } = req.body;

  // Check if user exists by username or email (depending on your schema)
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).json('Email does not exist');
    }

    const user = results[0];

    // Generate reset token
    const token = crypto.randomBytes(32).toString('hex');

    // Set token and expiration time (e.g., 1 hour)
    const expirationTime = new Date(Date.now() + 3600000); // Token valid for 1 hour

    db.query(`UPDATE users SET resetPasswordToken = ?, resetPasswordExpires = ? WHERE id = ?`, 
             [token, expirationTime, user.id], 
             async (updateErr) => {
      if (updateErr) {
        console.log(updateErr);
        return res.status(500).json('Error updating user record.');
      }

      // Send email with reset link
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
        `http://localhost:5173/resetPassword?token=${token}&email=${encodeURIComponent(user.email)}\n\n` + // Include token and email in link
        `If you did not request this, please ignore this email.\n`,
};
      try {
        await transporter.sendMail(mailOptions);
        res.status(200).json('Password reset link sent.');
      } catch (emailErr) {
        console.error('Error sending email:', emailErr);
        res.status(500).json('Error sending password reset email.');
      }
    });
  });
});


//reset password route
// Reset Password Route
app.post('/resetPassword', async (req, res) => {
  const { token, email, newPassword } = req.body;

  // Check if token is valid and not expired
  db.query("SELECT * FROM users WHERE email = ? AND resetPasswordToken = ? AND resetPasswordExpires > ?", 
           [email, token, new Date()], 
           async (err, results) => {
    if (err || results.length === 0) {
      return res.status(400).send('Invalid or expired token');
    }

    const user = results[0];

    // Hash the new password
    bcrypt.hash(newPassword, 10, async (err, hash) => {
      if (err) return res.status(500).json({ message: 'Error hashing password' });

      // Update user's password and clear reset fields
      db.query("UPDATE users SET password = ?, resetPasswordToken = NULL, resetPasswordExpires = NULL WHERE id = ?", 
               [hash, user.id], 
               (updateErr) => {
        if (updateErr) return res.status(500).send('Error updating password.');

        res.status(200).send('Password has been successfully updated.');
      });
    });
  });
});


// Middleware to authenticate JSON Web Tokens
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) return res.sendStatus(401); // If no token is provided, send unauthorized status

  jwt.verify(token, 'secret', (err, user) => { // Replace with your JWT secret
    if (err) return res.sendStatus(403); // If token is invalid or expired, send forbidden status

    req.user = user; // Attach user info to request object
    next(); // Proceed to the next middleware or route handler
  });
}

// Protected route example for authenticated users only
app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    message: 'This is a protected route',
    userId: req.user.id // Send back the authenticated user's ID
  });
});

// Server listening on specified port
const port = process.env.PORT || 5000; // Use environment variable or default to port 5000
app.listen(port, () => console.log("Server running on port: " + port + "By Brad")); // Start server and log to console





