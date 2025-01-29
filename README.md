1. Prerequisites
   
Install Node.js & npm:

Visit nodejs.org to download and install Node.js, which comes with npm (Node Package Manager).

2. Create a project folder:

For example, mkdir secure-auth-demo && cd secure-auth-demo.

3. Initialize Your Project
   
npm init -y

This generates a package.json with default settings.

4. Install Required Dependencies
Run the following in your project folder:

npm install express bcrypt express-session body-parser

express: Web framework for Node.js
bcrypt: For secure password hashing
express-session: For session management
body-parser: Parses form data from POST requests

5. Create Your server.js

Below is a minimal example of the server setup. It shows:

How to serve static files (like index.html)
How to handle registration and login
How to store passwords using bcrypt.hash()
How to compare passwords using bcrypt.compare()
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

// Setup sessions
app.use(session({
  secret: 'YourSessionSecretKey',
  resave: false,
  saveUninitialized: false
}));

// Our simple "in-memory" user store
let users = [];

// Serve static files (like index.html) from the 'views' folder
app.use(express.static('views'));

// Registration route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Hash the password with a salt
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  // Save the user with the hashed password
  users.push({ username, passwordHash });
  res.send('User registered successfully!');
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user in our "database"
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.send('Invalid username or password.');
  }

  // Compare the provided password with the stored (hashed) password
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    return res.send('Invalid username or password.');
  }

  // If successful, set the session
  req.session.user = { username };
  res.send(\`Welcome, \${username}! <a href="/protected">Go to protected page</a>\`);
});

// Protected route
app.get('/protected', (req, res) => {
  if (!req.session.user) {
    return res.send('You must be logged in to access this page.');
  }
  res.send(\`Hello, \${req.session.user.username}! <a href="/logout">Logout</a>\`);
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send('Error logging out.');
    }
    res.clearCookie('connect.sid');
    res.send('You have been logged out. <a href="/">Back to home</a>');
  });
});

// Start the server on port 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(\`Server running on http://localhost:\${PORT}\`);
});

6. Place Your index.html in the views Folder
7. 
Create a folder named views in your project root.
Move this index.html file into that folder.
With app.use(express.static('views')), Express automatically serves your index.html when someone visits http://localhost:3000.

8. Run Your App
   
node server.js
Open http://localhost:3000 in your browser. You should see the registration and login forms.
