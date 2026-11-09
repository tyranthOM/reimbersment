const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'reimbersment-super-secret-key-change-in-prod';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── PostgreSQL Connection on Render ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false }
    : false
});

// Auto-initialize schema in PostgreSQL
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS reimbs (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        token VARCHAR(32) UNIQUE NOT NULL,
        owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS reimb_access (
        id SERIAL PRIMARY KEY,
        reimb_id INT NOT NULL REFERENCES reimbs(id) ON DELETE CASCADE,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        role VARCHAR(32) DEFAULT 'viewer',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(reimb_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS expenses (
        id SERIAL PRIMARY KEY,
        reimb_id INT NOT NULL REFERENCES reimbs(id) ON DELETE CASCADE,
        amount NUMERIC(12, 2) NOT NULL,
        category VARCHAR(64) NOT NULL,
        date DATE NOT NULL,
        note TEXT,
        by_email VARCHAR(255),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_reimbs_token ON reimbs(token);
      CREATE INDEX IF NOT EXISTS idx_expenses_reimb_date ON expenses(reimb_id, date DESC);
    `);
    console.log('PostgreSQL database on Render initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

// ── Auth Middleware ──
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: missing token' });
  }

  const token = authHeader.split('Bearer ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, email }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
}

// Helper: Token Generator (e.g. ABCD-1234)
function genReimbToken() {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let t = "";
  for (let i = 0; i < 8; i++) {
    if (i === 4) t += "-";
    t += c[Math.floor(Math.random() * c.length)];
  }
  return t;
}

// ── Simple Email Login (No OAuth / No OTP) ──
app.post('/api/auth/login', async (req, res) => {
  try {
    let { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    email = email.trim().toLowerCase();

    // Upsert user into PostgreSQL
    const userRes = await pool.query(
      `INSERT INTO users (email) VALUES ($1)
       ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
       RETURNING id, email`,
      [email]
    );

    const user = userRes.rows[0];

    // Issue JWT session token (valid for 60 days)
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '60d' });

    console.log(`[AUTH] User logged in: ${user.email} (ID: ${user.id})`);

    res.json({
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// ── Application Endpoints (PostgreSQL) ──

// 1. Get all reimbs for user (owned + shared via token)
app.get('/api/reimbs', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const query = `
      SELECT r.id, r.name, r.token, r.created_at, u.email as owner_email,
        CASE WHEN r.owner_id = $1 THEN 'owner' ELSE 'viewer' END as role
      FROM reimbs r
      JOIN users u ON r.owner_id = u.id
      LEFT JOIN reimb_access ra ON r.id = ra.reimb_id AND ra.user_id = $1
      WHERE r.owner_id = $1 OR ra.user_id = $1
      ORDER BY r.created_at DESC
    `;
    const result = await pool.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching reimbs:', err);
    res.status(500).json({ error: 'Failed to fetch reimbs' });
  }
});

// 2. Create reimb (owner gets a token to share)
app.post('/api/reimbs', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Name is required' });
    }
    const userId = req.user.id;
    const email = req.user.email;
    const token = genReimbToken();

    const insertResult = await pool.query(
      `INSERT INTO reimbs (name, token, owner_id)
       VALUES ($1, $2, $3)
       RETURNING id, name, token, created_at`,
      [name.trim(), token, userId]
    );

    const created = insertResult.rows[0];
    res.status(201).json({
      ...created,
      owner_email: email,
      role: 'owner'
    });
  } catch (err) {
    console.error('Error creating reimb:', err);
    res.status(500).json({ error: 'Failed to create reimb' });
  }
});

// 3. Join reimb using token (viewer account connects to same reimb)
app.post('/api/reimbs/join', requireAuth, async (req, res) => {
  try {
    let { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    token = token.trim().toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/^(.{4})(.{4})$/, '$1-$2');

    const reimbQuery = await pool.query(
      `SELECT r.id, r.name, r.token, r.owner_id, u.email as owner_email
       FROM reimbs r
       JOIN users u ON r.owner_id = u.id
       WHERE r.token = $1`,
      [token]
    );

    if (reimbQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Invalid token — no reimb found with this code' });
    }

    const reimb = reimbQuery.rows[0];
    const userId = req.user.id;

    if (reimb.owner_id === userId) {
      return res.status(400).json({ error: 'You are the owner of this reimb' });
    }

    await pool.query(
      `INSERT INTO reimb_access (reimb_id, user_id, role)
       VALUES ($1, $2, 'viewer')
       ON CONFLICT (reimb_id, user_id) DO NOTHING`,
      [reimb.id, userId]
    );

    res.json({
      id: reimb.id,
      name: reimb.name,
      token: reimb.token,
      owner_email: reimb.owner_email,
      role: 'viewer'
    });
  } catch (err) {
    console.error('Error joining reimb:', err);
    res.status(500).json({ error: 'Failed to join reimb' });
  }
});

// 4. Get expenses for a reimb (both accounts fetch this!)
app.get('/api/reimbs/:id/expenses', requireAuth, async (req, res) => {
  try {
    const reimbId = parseInt(req.params.id, 10);
    const userId = req.user.id;

    // Check permission (owner or viewer)
    const accessCheck = await pool.query(
      `SELECT r.id FROM reimbs r
       LEFT JOIN reimb_access ra ON r.id = ra.reimb_id AND ra.user_id = $2
       WHERE r.id = $1 AND (r.owner_id = $2 OR ra.user_id = $2)`,
      [reimbId, userId]
    );

    if (accessCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const expensesQuery = await pool.query(
      `SELECT id, amount, category, TO_CHAR(date, 'YYYY-MM-DD') as date, note, by_email, created_at
       FROM expenses
       WHERE reimb_id = $1
       ORDER BY date DESC, id DESC`,
      [reimbId]
    );

    res.json(expensesQuery.rows);
  } catch (err) {
    console.error('Error getting expenses:', err);
    res.status(500).json({ error: 'Failed to load expenses' });
  }
});

// 5. Add expense (owner only)
app.post('/api/reimbs/:id/expenses', requireAuth, async (req, res) => {
  try {
    const reimbId = parseInt(req.params.id, 10);
    const { amount, category, date, note } = req.body;
    const userId = req.user.id;
    const email = req.user.email;

    if (!amount || isNaN(amount) || Number(amount) <= 0 || !category || !date) {
      return res.status(400).json({ error: 'Missing or invalid fields' });
    }

    const ownerCheck = await pool.query(
      `SELECT id FROM reimbs WHERE id = $1 AND owner_id = $2`,
      [reimbId, userId]
    );
    if (ownerCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Only the owner can add expenses' });
    }

    const insertResult = await pool.query(
      `INSERT INTO expenses (reimb_id, amount, category, date, note, by_email)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, amount, category, TO_CHAR(date, 'YYYY-MM-DD') as date, note, by_email, created_at`,
      [reimbId, Number(amount), category, date, (note || '').trim(), email]
    );

    res.status(201).json(insertResult.rows[0]);
  } catch (err) {
    console.error('Error adding expense:', err);
    res.status(500).json({ error: 'Failed to save expense' });
  }
});

// 6. Delete expense (owner only)
app.delete('/api/expenses/:id', requireAuth, async (req, res) => {
  try {
    const expenseId = parseInt(req.params.id, 10);
    const userId = req.user.id;

    const deleteResult = await pool.query(
      `DELETE FROM expenses
       WHERE id = $1 AND reimb_id IN (SELECT id FROM reimbs WHERE owner_id = $2)
       RETURNING id`,
      [expenseId, userId]
    );

    if (deleteResult.rowCount === 0) {
      return res.status(403).json({ error: 'Not allowed to delete this expense' });
    }

    res.json({ success: true, id: expenseId });
  } catch (err) {
    console.error('Error deleting expense:', err);
    res.status(500).json({ error: 'Failed to delete expense' });
  }
});

// Frontend fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
if (process.env.DATABASE_URL) {
  initDb().then(() => {
    app.listen(port, () => console.log(`Server listening on port ${port}`));
  });
} else {
  console.warn('DATABASE_URL not set. Running server without DB init...');
  app.listen(port, () => console.log(`Server listening on port ${port}`));
}
