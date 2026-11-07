const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── Database Setup ──
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost') 
    ? { rejectUnauthorized: false } 
    : false
});

// Initialize database tables
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        uid VARCHAR(128) PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS reimbs (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        token VARCHAR(32) UNIQUE NOT NULL,
        owner_uid VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS reimb_access (
        id SERIAL PRIMARY KEY,
        reimb_id INT NOT NULL REFERENCES reimbs(id) ON DELETE CASCADE,
        user_uid VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
        role VARCHAR(32) DEFAULT 'viewer',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(reimb_id, user_uid)
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
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
  } finally {
    client.release();
  }
}

// ── Firebase Admin Auth Setup ──
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
  } catch (e) {
    console.warn('Could not parse FIREBASE_SERVICE_ACCOUNT, initializing default app:', e.message);
    admin.initializeApp();
  }
} else {
  // Uses default credentials or basic token payload check if no cert supplied
  try {
    admin.initializeApp();
  } catch(e) {}
}

// Auth Middleware: verifies token & upserts user in Postgres
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
  }

  const idToken = authHeader.split('Bearer ')[1];
  try {
    let uid, email;
    try {
      const decoded = await admin.auth().verifyIdToken(idToken);
      uid = decoded.uid;
      email = decoded.email || '';
    } catch (fbErr) {
      // Fallback for decode if service account key isn't configured in development
      const decodedPayload = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64').toString());
      uid = decodedPayload.user_id || decodedPayload.sub;
      email = decodedPayload.email || '';
    }

    if (!uid) {
      return res.status(401).json({ error: 'Invalid token payload' });
    }

    // Upsert user
    await pool.query(
      `INSERT INTO users (uid, email) VALUES ($1, $2)
       ON CONFLICT (uid) DO UPDATE SET email = EXCLUDED.email`,
      [uid, email]
    );

    req.user = { uid, email };
    next();
  } catch (err) {
    console.error('Auth verification failed:', err);
    res.status(401).json({ error: 'Authentication failed' });
  }
}

// Helper to generate token
function genToken() {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let t = "";
  for (let i = 0; i < 8; i++) {
    if (i === 4) t += "-";
    t += c[Math.floor(Math.random() * c.length)];
  }
  return t;
}

// ── API Routes ──

// 1. Get all reimbs (owned + shared)
app.get('/api/reimbs', requireAuth, async (req, res) => {
  try {
    const { uid } = req.user;
    const query = `
      SELECT r.id, r.name, r.token, r.created_at, u.email as owner_email,
        CASE WHEN r.owner_uid = $1 THEN 'owner' ELSE 'viewer' END as role
      FROM reimbs r
      JOIN users u ON r.owner_uid = u.uid
      LEFT JOIN reimb_access ra ON r.id = ra.reimb_id AND ra.user_uid = $1
      WHERE r.owner_uid = $1 OR ra.user_uid = $1
      ORDER BY r.created_at DESC
    `;
    const result = await pool.query(query, [uid]);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching reimbs:', err);
    res.status(500).json({ error: 'Failed to fetch reimbs' });
  }
});

// 2. Create reimb
app.post('/api/reimbs', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Name is required' });
    }
    const { uid, email } = req.user;
    const token = genToken();

    const insertResult = await pool.query(
      `INSERT INTO reimbs (name, token, owner_uid)
       VALUES ($1, $2, $3)
       RETURNING id, name, token, created_at`,
      [name.trim(), token, uid]
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

// 3. Join reimb with token
app.post('/api/reimbs/join', requireAuth, async (req, res) => {
  try {
    let { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    token = token.trim().toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/^(.{4})(.{4})$/, '$1-$2');

    const reimbQuery = await pool.query(
      `SELECT r.id, r.name, r.token, r.owner_uid, u.email as owner_email
       FROM reimbs r
       JOIN users u ON r.owner_uid = u.uid
       WHERE r.token = $1`,
      [token]
    );

    if (reimbQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Token not found' });
    }

    const reimb = reimbQuery.rows[0];
    const { uid } = req.user;

    if (reimb.owner_uid === uid) {
      return res.status(400).json({ error: 'You are already the owner of this reimb' });
    }

    // Insert access permission
    await pool.query(
      `INSERT INTO reimb_access (reimb_id, user_uid, role)
       VALUES ($1, $2, 'viewer')
       ON CONFLICT (reimb_id, user_uid) DO NOTHING`,
      [reimb.id, uid]
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

// 4. Get expenses for a reimb
app.get('/api/reimbs/:id/expenses', requireAuth, async (req, res) => {
  try {
    const reimbId = parseInt(req.params.id, 10);
    const { uid } = req.user;

    // Check permission
    const accessCheck = await pool.query(
      `SELECT r.id FROM reimbs r
       LEFT JOIN reimb_access ra ON r.id = ra.reimb_id AND ra.user_uid = $2
       WHERE r.id = $1 AND (r.owner_uid = $2 OR ra.user_uid = $2)`,
      [reimbId, uid]
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
    const { uid, email } = req.user;

    if (!amount || isNaN(amount) || amount <= 0 || !category || !date) {
      return res.status(400).json({ error: 'Missing or invalid fields' });
    }

    // Verify owner
    const ownerCheck = await pool.query(
      `SELECT id FROM reimbs WHERE id = $1 AND owner_uid = $2`,
      [reimbId, uid]
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
    const { uid } = req.user;

    const deleteResult = await pool.query(
      `DELETE FROM expenses
       WHERE id = $1 AND reimb_id IN (SELECT id FROM reimbs WHERE owner_uid = $2)
       RETURNING id`,
      [expenseId, uid]
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
