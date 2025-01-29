const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');


// Create an Express app
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

// Configure sessions
app.use(session({
  secret: 'YourSessionSecretKeyGoesHere',
  resave: false,
  saveUninitialized: false,
}));

// Fake user "database"
let users = []; 
// Each user object: { username: 'X', passwordHash: '...' }

// Serve static files from the "views" folder
app.use(express.static('views'));

// 1. Registration Route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if username is taken
  if (users.some(u => u.username === username)) {
    return res.send('Username already taken! <a href="/">Go back</a>');
  }

  // Hash password
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  // Store user with hashed password
  users.push({ username, passwordHash });
  
  res.send('User registered successfully. <a href="/">Go back</a>');
});

// 2. Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.send('Invalid username or password. <a href="/">Go back</a>');
  }

  // Compare password with stored hash
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.send('Invalid username or password. <a href="/">Go back</a>');
  }

  // If success, store user in session
  req.session.user = { username };
  res.send(`Welcome, ${username}! <a href="/protected">Go to protected page</a>`);
});

// 3. Protected Route
app.get('/protected', (req, res) => {
  if (!req.session.user) {
    return res.send('You are not logged in! <a href="/">Go to home</a>');
  }
  res.send(`You are logged in as ${req.session.user.username}. <a href="/logout">Logout</a>`);
});

// 4. Logout Route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send('Error logging out');
    }
    res.clearCookie('connect.sid');
    res.send('You have logged out. <a href="/">Go to home</a>');
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on https://localhost:${PORT}`);
});