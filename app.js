const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const helmet = require('helmet');
const winston = require('winston');

const app = express();

// ==========================================
// WINSTON LOGGER SETUP
// ==========================================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

logger.info('Application started');

// Fix: Secure HTTP headers with Helmet
app.use(helmet());

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ 
  secret: 'secureSecretKey123', 
  resave: false, 
  saveUninitialized: false 
}));

// User database
const users = [];

// Home Page
app.get('/', (req, res) => {
  logger.info('Home page visited');
  res.send(`
    <h1>Welcome to User Management System</h1>
    <a href="/login">Secure Login</a> | 
    <a href="/signup">Signup</a> | 
    <a href="/vulnerable-login">Vulnerable Login (SQL Injection Test)</a>
  `);
});

// ==========================================
// VULNERABLE LOGIN (For SQL Injection Test)
// ==========================================
app.get('/vulnerable-login', (req, res) => {
  logger.warn('Vulnerable login page visited');
  res.send(`
    <h1>Vulnerable Login (SQL Injection Test)</h1>
    <p style="color:red">Warning: This page is intentionally vulnerable!</p>
    <form method="POST" action="/vulnerable-login">
      <input name="username" placeholder="Username" /><br><br>
      <input name="password" type="password" placeholder="Password" /><br><br>
      <button type="submit">Login</button>
    </form>
    <br>
    <p>Try entering: <b>admin' OR '1'='1</b> as username</p>
    <a href="/">Back to Home</a>
  `);
});

app.post('/vulnerable-login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // VULNERABLE: Simulating SQL Injection
  if (username.includes("' OR '1'='1") || username.includes("' or '1'='1")) {
    logger.error(`SQL Injection attack detected! Username: ${username}`);
    return res.send(`
      <h1 style="color:red">⚠️ SQL Injection Successful!</h1>
      <p>You bypassed authentication without a password!</p>
      <p>This is how SQL Injection works in real databases.</p>
      <a href="/vulnerable-login">Try again</a> | <a href="/">Home</a>
    `);
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    logger.warn(`Failed login attempt on vulnerable page. Username: ${username}`);
    return res.status(401).send('Invalid credentials. <a href="/vulnerable-login">Try again</a>');
  }

  res.send('Logged in successfully!');
});

// ==========================================
// SECURE LOGIN
// ==========================================
app.get('/login', (req, res) => {
  res.send(`
    <h1>Secure Login</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username" /><br><br>
      <input name="password" type="password" placeholder="Password" /><br><br>
      <button type="submit">Login</button>
    </form>
    <a href="/">Back to Home</a>
  `);
});

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Fix: Validate inputs are not empty
  if (validator.isEmpty(username) || validator.isEmpty(password)) {
    logger.warn('Login attempt with empty fields');
    return res.status(400).send('Username and password are required. <a href="/login">Try again</a>');
  }

  // Fix: Reject any SQL Injection attempts
  if (username.includes("'") || username.includes('"') || username.includes('--')) {
    logger.error(`SQL Injection attempt on secure login! Username: ${username}`);
    return res.status(400).send('Invalid characters detected! <a href="/login">Try again</a>');
  }

  const user = users.find(u => u.username === username);

  if (!user) {
    logger.warn(`Failed login attempt. Username: ${username}`);
    return res.status(401).send('Invalid credentials. <a href="/login">Try again</a>');
  }

  // Fix: Compare hashed password using bcrypt
  const isMatch = await bcrypt.compare(password, user.password);

  if (isMatch) {
    req.session.user = { id: user.id, username: user.username, email: user.email };

    // Fix: Generate JWT token
    const token = jwt.sign({ id: user.id }, 'jwtSecretKey123', { expiresIn: '1h' });
    req.session.token = token;

    logger.info(`User logged in successfully. Username: ${username}`);
    res.redirect('/profile');
  } else {
    logger.warn(`Wrong password attempt. Username: ${username}`);
    res.status(401).send('Invalid credentials. <a href="/login">Try again</a>');
  }
});

// Signup Page
app.get('/signup', (req, res) => {
  res.send(`
    <h1>Signup</h1>
    <form method="POST" action="/signup">
      <input name="username" placeholder="Username" /><br><br>
      <input name="email" placeholder="Email" /><br><br>
      <input name="password" type="password" placeholder="Password" /><br><br>
      <button type="submit">Signup</button>
    </form>
    <a href="/">Back to Home</a>
  `);
});

app.post('/signup', async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  // Fix: Validate inputs
  if (validator.isEmpty(username) || validator.isEmpty(email) || validator.isEmpty(password)) {
    logger.warn('Signup attempt with empty fields');
    return res.status(400).send('All fields are required. <a href="/signup">Try again</a>');
  }

  // Fix: Validate email format
  if (!validator.isEmail(email)) {
    logger.warn(`Invalid email format used during signup: ${email}`);
    return res.status(400).send('Invalid email format. <a href="/signup">Try again</a>');
  }

  // Fix: Validate password length
  if (!validator.isLength(password, { min: 6 })) {
    logger.warn('Signup attempt with short password');
    return res.status(400).send('Password must be at least 6 characters. <a href="/signup">Try again</a>');
  }

  // Fix: Sanitize username to prevent XSS
  const sanitizedUsername = validator.escape(username);

  // Fix: Hash password using bcrypt
  const hashedPassword = await bcrypt.hash(password, 10);

  users.push({ 
    id: users.length + 1, 
    username: sanitizedUsername, 
    password: hashedPassword, 
    email: email 
  });

  logger.info(`New user signed up. Username: ${sanitizedUsername}`);
  res.send(`<h1>Welcome ${sanitizedUsername}!</h1><p>Account created successfully!</p><a href="/login">Login</a>`);
});

// Profile Page
app.get('/profile', (req, res) => {
  if (!req.session.user || !req.session.token) {
    logger.warn('Unauthorized access attempt to profile page');
    return res.redirect('/login');
  }

  // Fix: Verify JWT token
  try {
    jwt.verify(req.session.token, 'jwtSecretKey123');
  } catch (err) {
    logger.error('Invalid JWT token detected');
    return res.redirect('/login');
  }

  const user = req.session.user;
  logger.info(`Profile page visited by: ${user.username}`);
  res.send(`
    <h1>Profile</h1>
    <p>Username: ${user.username}</p>
    <p>Email: ${user.email}</p>
    <a href="/logout">Logout</a>
  `);
});

// Logout
app.get('/logout', (req, res) => {
  if (req.session.user) {
    logger.info(`User logged out. Username: ${req.session.user.username}`);
  }
  req.session.destroy();
  res.redirect('/');
});

// Start server
app.listen(3000, () => {
  console.log('Server running at http://localhost:3000');
});