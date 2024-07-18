const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const app = express();

// Use sessions for tracking user login status
app.use(session({
  secret: 'your_secret_key', // change this to a random string for production
  resave: false,
  saveUninitialized: false,
}));

// Parse incoming requests
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Example in-memory database (replace with a real database like MongoDB or MySQL)
let users = [];

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
};

// Register a new user
app.post('/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const newUser = {
      id: users.length + 1,
      username: req.body.username,
      email: req.body.email,
      password: hashedPassword,
    };
    users.push(newUser); // In reality, save to database
    res.status(201).send('User registered successfully');
  } catch {
    res.status(500).send('Failed to register user');
  }
});

// User login
app.post('/login', async (req, res) => {
  const user = users.find(user => user.username === req.body.username);
  if (user == null) {
    return res.status(400).send('User not found');
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      req.session.user = user;
      res.send('Login successful');
    } else {
      res.status(401).send('Login failed');
    }
  } catch {
    res.status(500).send('Login failed');
  }
});

// Protected route example
app.get('/protected', requireAuth, (req, res) => {
  res.send('Protected route accessed');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Logout failed');
    }
    res.send('Logout successful');
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
