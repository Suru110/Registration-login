const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./db');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'auth-app-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// ─── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  res.redirect('/login.html');
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Redirect root to login
app.get('/', (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect('/dashboard.html');
  }
  res.redirect('/login.html');
});

// REGISTER
app.post('/api/register', (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  // Basic validation
  if (!username || !email || !password || !confirmPassword) {
    return res.json({ success: false, message: 'All fields are required.' });
  }
  if (username.length < 3) {
    return res.json({ success: false, message: 'Username must be at least 3 characters.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.json({ success: false, message: 'Please enter a valid email address.' });
  }
  if (password.length < 6) {
    return res.json({ success: false, message: 'Password must be at least 6 characters.' });
  }
  if (password !== confirmPassword) {
    return res.json({ success: false, message: 'Passwords do not match.' });
  }

  // Check if username or email already exists
  db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
    if (err) {
      return res.json({ success: false, message: 'Database error. Please try again.' });
    }
    if (row) {
      return res.json({ success: false, message: 'Username or email already in use.' });
    }

    // Hash password and insert user
    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        return res.json({ success: false, message: 'Error processing password.' });
      }

      db.run(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, hash],
        function (err) {
          if (err) {
            return res.json({ success: false, message: 'Failed to create account.' });
          }
          res.json({ success: true, message: 'Account created successfully! Please log in.' });
        }
      );
    });
  });
});

// LOGIN
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.json({ success: false, message: 'Username and password are required.' });
  }

  db.get(
    'SELECT * FROM users WHERE username = ? OR email = ?',
    [username, username],
    (err, user) => {
      if (err) {
        return res.json({ success: false, message: 'Database error. Please try again.' });
      }
      if (!user) {
        return res.json({ success: false, message: 'Invalid username or password.' });
      }

      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err || !isMatch) {
          return res.json({ success: false, message: 'Invalid username or password.' });
        }

        // Set session
        req.session.userId = user.id;
        req.session.username = user.username;

        res.json({ success: true, message: 'Login successful!' });
      });
    }
  );
});

// LOGOUT
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.json({ success: false, message: 'Logout failed.' });
    }
    res.json({ success: true });
  });
});

// GET current user (for dashboard)
app.get('/api/me', requireAuth, (req, res) => {
  db.get(
    'SELECT id, username, email, created_at FROM users WHERE id = ?',
    [req.session.userId],
    (err, user) => {
      if (err || !user) {
        return res.json({ success: false, message: 'User not found.' });
      }
      res.json({ success: true, user });
    }
  );
});

// ─── Start server ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
