/************************************************
 * server.js - HTTPS with Secure Authentication
 ************************************************/
const express = require('express');
const https = require('https');
const fs = require('fs');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

// 1. Create the Express app
const app = express();

// 2. Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// 3. Session configuration
app.use(session({
  secret: 'YourSessionSecretKey',
  resave: false,
  saveUninitialized: false
}));

// 4. Simple in-memory "database" for users
let users = []; 
// Each user object will look like: { username: 'abc', passwordHash: '...' }

// 5. Serve static files (like index.html) from the "views" folder
app.use(express.static('views'));

/************************************************
 *                Routes
 ************************************************/
// 6. Registration route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  // Hash the password
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  // Save user with hashed password
  users.push({ username, passwordHash });
  
  res.send('User registered successfully! <a href="/">Go back</a>');
});

// 7. Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  // Find user by username
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.send('Invalid username or password. <a href="/">Try again</a>');
  }

  // Compare provided password with stored hash
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.send('Invalid username or password. <a href="/">Try again</a>');
  }

  // If match, store user data in session
  req.session.user = { username };
  res.send(`Welcome, ${username}! <a href="/protected">Go to protected page</a>`);
});

// 8. Protected route
app.get('/protected', (req, res) => {
  if (!req.session.user) {
    return res.send('You must be logged in to see this page. <a href="/">Home</a>');
  }
  res.send(`Hello, ${req.session.user.username}! <a href="/logout">Logout</a>`);
});

// 9. Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send('Error logging out. <a href="/">Home</a>');
    }
    res.clearCookie('connect.sid');
    res.send('You have been logged out. <a href="/">Home</a>');
  });
});

/************************************************
 *           HTTPS Server Configuration
 ************************************************/
// 10. Read SSL certificate and key
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

// 11. Define the server port
const PORT = process.env.PORT || 3000;

// 12. Create an HTTPS server
https.createServer(options, app).listen(PORT, () => {
  console.log(`Server running on https://localhost:${PORT}`);
});
