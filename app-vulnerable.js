const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: '123456', resave: true, saveUninitialized: true }));

// Fake user database (vulnerable - passwords stored as plain text)
const users = [
  { id: 1, username: 'admin', password: 'admin123', email: 'admin@test.com' },
  { id: 2, username: 'user1', password: 'password', email: 'user1@test.com' }
];

// Home Page
app.get('/', (req, res) => {
  res.send(`
    <h1>Welcome to User Management System</h1>
    <a href="/login">Login</a> | 
    <a href="/signup">Signup</a>
  `);
});

// Login Page (Vulnerable to SQL Injection simulation)
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username" /><br><br>
      <input name="password" type="password" placeholder="Password" /><br><br>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Vulnerable: no input validation
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    req.session.user = user;
    res.redirect('/profile');
  } else {
    res.send('Invalid credentials. <a href="/login">Try again</a>');
  }
});

// Signup Page (Vulnerable to XSS)
app.get('/signup', (req, res) => {
  res.send(`
    <h1>Signup</h1>
    <form method="POST" action="/signup">
      <input name="username" placeholder="Username" /><br><br>
      <input name="email" placeholder="Email" /><br><br>
      <input name="password" type="password" placeholder="Password" /><br><br>
      <button type="submit">Signup</button>
    </form>
  `);
});

app.post('/signup', (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  // Vulnerable: password stored as plain text, no input sanitization
  users.push({ id: users.length + 1, username, password, email });

  // Vulnerable to XSS: directly renders user input without sanitization
  res.send(`<h1>Welcome ${username}!</h1><p>Account created successfully!</p><a href="/login">Login</a>`);
});

// Vulnerable Login Page (SQL Injection)
app.get('/vulnerable-login', (req, res) => {
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

  // Vulnerable: SQL Injection simulation
  // No input validation or sanitization
  if (username.includes("' OR '1'='1") || username.includes("' or '1'='1")) {
    return res.send(`
      <h1 style="color:red">⚠️ SQL Injection Successful!</h1>
      <p>You bypassed authentication without a password!</p>
      <p>This is how SQL Injection works in real databases.</p>
      <a href="/vulnerable-login">Try again</a> | <a href="/">Home</a>
    `);
  }

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).send('Invalid credentials. <a href="/vulnerable-login">Try again</a>');
  }

  res.send('Logged in successfully!');
});

// Profile Page
app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  const user = req.session.user;
  res.send(`
    <h1>Profile</h1>
    <p>Username: ${user.username}</p>
    <p>Email: ${user.email}</p>
    <a href="/logout">Logout</a>
  `);
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Start server
app.listen(3000, () => {
  console.log('Vulnerable server running at http://localhost:3000');
});