import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { db } from '../db.js';

const router = express.Router();

// Register a new user
router.post('/register', registerUser);

// Login a user
router.post('/login', loginUser);

// Logout a user
router.post('/logout', logoutUser);

// Get user profile
router.get('/profile', authenticateUser, getUserProfile);

// Middleware to authenticate user using JWT
function authenticateUser(req, res, next) {
  const token = req.cookies.access_token;
  if (!token) return res.status(401).json('Not authenticated!');

  jwt.verify(token, process.env.JWT_SECRET || 'your_default_secret', (err, userInfo) => {
    if (err) return res.status(403).json('Token is not valid!');
    
    req.userInfo = userInfo;
    next();
  });
}

// Controller function to register a new user
async function registerUser(req, res) {
  const { username, password } = req.body;

  // Check if the username already exists
  const userExists = await checkUserExists(username);
  if (userExists) return res.status(400).json('Username already exists!');

  // Hash the password before storing it in the database
  const hashedPassword = await bcrypt.hash(password, 10);

  const q = 'INSERT INTO users(`username`, `password`) VALUES (?, ?)';
  const values = [username, hashedPassword];

  db.query(q, values, (err, data) => {
    if (err) return res.status(200).json(err);

    return res.json('User registered successfully.');
  });
}

// Controller function to login a user
async function loginUser(req, res) {
  const { username, password } = req.body;

  // Check if the username exists
  const userExists = await checkUserExists(username);
  if (!userExists) return res.status(401).json('Invalid credentials.');

  // Retrieve the hashed password from the database
  const q = 'SELECT `id`, `password` FROM users WHERE `username` = ?';
  db.query(q, [username], async (err, data) => {
    if (err) return res.status(500).json(err);

    const user = data[0];

    // Compare the provided password with the hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json('Invalid credentials.');

    // Create a JWT for user authentication
    const token = jwt.sign({ id: user.id, username: username }, process.env.JWT_SECRET || 'your_default_secret');

    // Set the JWT as a cookie
    res.cookie('access_token', token, { httpOnly: true });

    return res.json('Login successful.');
  });
}

// Controller function to logout a user
function logoutUser(req, res) {
  // Clear the token cookie on the client side
  res.clearCookie('access_token');

  // Respond with a success message
  res.json('Logout successful.');
}

// Controller function to get user profile
function getUserProfile(req, res) {
  const userId = req.userInfo.id;

  const q = 'SELECT `id`, `username` FROM users WHERE `id` = ?';
  db.query(q, [userId], (err, data) => {
    if (err) return res.status(500).json(err);

    const user = data[0];
    return res.status(200).json(user);
  });
}

// Helper function to check if a user with a given username already exists
async function checkUserExists(username) {
  return new Promise((resolve, reject) => {
    const q = 'SELECT COUNT(*) as count FROM users WHERE `username` = ?';
    db.query(q, [username], (err, data) => {
      if (err) reject(err);

      const count = data[0].count;
      resolve(count > 0);
    });
  });
}

export default router;