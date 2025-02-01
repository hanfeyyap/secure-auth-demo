1. Prerequisites
Install Node.js & npm:
Visit nodejs.org to download and install Node.js, which comes with npm (Node Package Manager).
Create a project folder:
For example, mkdir secure-auth-demo && cd secure-auth-demo.
2. Initialize Your Project
npm init -y
This generates a package.json with default settings.

3. Install Required Dependencies
Run the following in your project folder:

npm install express bcrypt express-session body-parser express-rate-limit zxcvbn
express: Web framework for Node.js
bcrypt: For secure password hashing
express-session: For session management
body-parser: Parses form data from POST requests
express-rate-limit: For rate limiting login attempts
zxcvbn: For checking password strength

4. Generate Self-Signed Certificate (for HTTPS in Development)
If you want to enable HTTPS locally, run the following command in your project folder:

openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
This will create two files in your current directory: key.pem and cert.pem. These are used for TLS encryption. (Your browser will warn you about a self-signed certificate, but it’s fine for testing.)

5. Create Your server.js with HTTPS & Secure Auth
Here’s a sample server.js that uses HTTPS, bcrypt (for hashing), express-session (for session management), express-rate-limit (for rate limiting), and zxcvbn (for password strength checking):

const express = require('express');
const https = require('https');
const fs = require('fs');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const zxcvbn = require('zxcvbn');

// 1. Create the Express app
const app = express();

// 2. Middleware to parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// 3. Session configuration
app.use(session({
  secret: 'YourSessionSecretKey',
  resave: false,
  saveUninitialized: false,
}));

// 4. In-memory user store (for demo)
let users = []; 
// Example user object: { username: 'testuser', passwordHash: '...' }

/************************************************
 *                Rate Limiting
 ************************************************/
const maxAttempts = 5;
const attempts = {};

// Rate limiter for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: maxAttempts, // Limit each IP to 5 login requests per `window` (here, per 15 minutes)
  handler: (req, res) => {
    const remainingTime = Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000 / 60);
    res.send(\`Too many login attempts from this IP. Please try again after \${remainingTime} minutes.\`);
  }
});

/************************************************
 *                Routes
 ************************************************/
// Serve static files from "views" (like index.html)
app.use(express.static('views'));

// Route for the root URL
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});
// Registration route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check password strength
  const result = zxcvbn(password);
  if (result.score < 3) { // Score ranges from 0 to 4; 3 is a reasonable threshold
    const feedback = result.feedback.suggestions.join(' ');
    return res.send(\`Password is too weak. Please choose a stronger password. Tips: \${feedback}\`);
  }

  // Hash the password
  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  // Save user with hashed password
  users.push({ username, passwordHash });
  res.send('User registered successfully! Go back');
});

// Login route with rate limiter
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;

  // Initialize attempts for the IP if not already set
  if (!attempts[ip]) {
    attempts[ip] = 0;
  }

  // Find user by username
  const user = users.find(u => u.username === username);
  if (!user) {
    attempts[ip]++;
    const remainingAttempts = maxAttempts - attempts[ip];
    return res.send(\`Invalid username or password. You have \${remainingAttempts} attempts left. Try again\`);
  }

  // Compare provided password with stored hash
  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) {
    attempts[ip]++;
    const remainingAttempts = maxAttempts - attempts[ip];
    return res.send(\`Invalid username or password. You have \${remainingAttempts} attempts left. Try again\`);
  }

  // If match, store user data in session
  req.session.user = { username };
  attempts[ip] = 0; // Reset login attempts on successful login
  res.send(\`Welcome, \${username}! Go to protected page\`);
});

// Protected route
app.get('/protected', (req, res) => {
  if (!req.session.user) {
    return res.send('You must be logged in to see this page. Home');
  }
  res.send(\`Hello, \${req.session.user.username}! Logout\`);
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send('Error logging out. Home');
    }
    res.clearCookie('connect.sid');
    res.send('You have been logged out. Home');
  });
});

/************************************************
 *           HTTPS Server Configuration
 ************************************************/
// Read SSL certificate & key for HTTPS
const options = {
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem')
};

// Start HTTPS server on port 3000
const PORT = process.env.PORT || 3000;
https.createServer(options, app).listen(PORT, () => {
  console.log(\`Server running on https://localhost:\${PORT}\`);
});
6. Folder Structure
A typical layout:

secure-auth-demo/
├── key.pem
├── cert.pem
├── server.js
├── package.json
├── package-lock.json
└── views
    └── index.html
Make sure index.html (the file you're reading now) is inside the views folder, so express.static('views') can serve it.

7. Running the App
In your terminal, from the project root:

node server.js
Open https://localhost:3000 in your browser. You’ll likely see a warning about the certificate (because it’s self-signed). Click “Advanced” → “Proceed” to continue.

8. Testing Registration & Login
Register: Enter a username/password on the Register form. Check your server logs if you want to see the stored hashed password (for demonstration).
Login: Enter the same username/password. If correct, you’ll see a welcome message with a link to the protected page.
Protected Route: After logging in, you can visit /protected. If you log out or clear cookies, you’ll be denied access until you log in again.

9. Folder Structure
A typical layout:

secure-auth-demo/
├── key.pem
├── cert.pem
├── server.js
├── package.json
├── package-lock.json
└── views
    └── index.html
Make sure index.html (the file you're reading now) is inside the views folder, so express.static('views') can serve it.

10. Running the App
In your terminal, from the project root:

node server.js
Open https://localhost:3000 in your browser. You’ll likely see a warning about the certificate (because it’s self-signed). Click “Advanced” → “Proceed” to continue.

11. Testing Registration & Login
Register: Enter a username/password on the Register form. Check your server logs if you want to see the stored hashed password (for demonstration).
Login: Enter the same username/password. If correct, you’ll see a welcome message with a link to the protected page.
Protected Route: After logging in, you can visit /protected. If you log out or clear cookies, you’ll be denied access until you log in again.
12. Key Security Concepts
HTTPS (TLS/SSL): Encrypts all traffic between client and server, preventing eavesdropping of passwords or session IDs.
Hashing & Salting Passwords: We use bcrypt.hash() to store only the scrambled hash, never the plaintext password.
Session Management: express-session assigns a session ID cookie to the browser, storing session data server-side. The user doesn’t need to re-send their password on each request.
Rate Limiting: express-rate-limit restricts the number of login attempts from a single IP address to prevent brute force attacks.
Password Strength Checking: zxcvbn evaluates the strength of passwords and provides feedback on how to create stronger passwords.
