const express = require('express');
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'reimbersment-super-secret-key-change-in-prod';
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://ombhalerao25_db_user:4ZXZBeujkB3FgxgA@reimb.ptowlta.mongodb.net/?retryWrites=true&w=majority&appName=reimb";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── MongoDB Atlas Connection ──
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB Atlas successfully!'))
  .catch(err => console.error('MongoDB Atlas connection error:', err));

// ── Mongoose Schemas & Models ──
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  createdAt: { type: Date, default: Date.now }
});

const reimbSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  token: { type: String, required: true, unique: true, uppercase: true },
  ownerEmail: { type: String, required: true, lowercase: true },
  viewers: [{ type: String, lowercase: true }],
  createdAt: { type: Date, default: Date.now }
});

const expenseSchema = new mongoose.Schema({
  reimbId: { type: mongoose.Schema.Types.ObjectId, ref: 'Reimb', required: true },
  amount: { type: Number, required: true },
  category: { type: String, required: true },
  date: { type: String, required: true }, // 'YYYY-MM-DD'
  note: { type: String, default: '' },
  byEmail: { type: String, lowercase: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Reimb = mongoose.model('Reimb', reimbSchema);
const Expense = mongoose.model('Expense', expenseSchema);

// ── JWT Auth Middleware ──
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: missing token' });
  }

  const token = authHeader.split('Bearer ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { email }
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

// ── Simple Email Login ──
app.post('/api/auth/login', async (req, res) => {
  try {
    let { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Please enter a valid email address' });
    }
    email = email.trim().toLowerCase();

    // Find or create user
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email });
    }

    // Issue JWT token (valid for 60 days)
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '60d' });

    console.log(`[AUTH] User logged in: ${user.email}`);

    res.json({
      token,
      user: { email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Database error: ' + err.message });
  }
});

// ── Application Endpoints (MongoDB) ──

// 1. Get all reimbs for current user (owned or shared via token)
app.get('/api/reimbs', requireAuth, async (req, res) => {
  try {
    const email = req.user.email;
    const reimbs = await Reimb.find({
      $or: [{ ownerEmail: email }, { viewers: email }]
    }).sort({ createdAt: -1 });

    const formatted = reimbs.map(r => ({
      id: r._id,
      name: r.name,
      token: r.token,
      owner_email: r.ownerEmail,
      role: r.ownerEmail === email ? 'owner' : 'viewer',
      created_at: r.createdAt
    }));

    res.json(formatted);
  } catch (err) {
    console.error('Error fetching reimbs:', err);
    res.status(500).json({ error: 'Failed to fetch reimbs: ' + err.message });
  }
});

// 2. Create reimb
app.post('/api/reimbs', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ error: 'Name is required' });
    }
    const email = req.user.email;
    const token = genReimbToken();

    const created = await Reimb.create({
      name: name.trim(),
      token,
      ownerEmail: email,
      viewers: []
    });

    res.status(201).json({
      id: created._id,
      name: created.name,
      token: created.token,
      owner_email: created.ownerEmail,
      role: 'owner',
      created_at: created.createdAt
    });
  } catch (err) {
    console.error('Error creating reimb:', err);
    res.status(500).json({ error: 'Failed to create reimb: ' + err.message });
  }
});

// 3. Join reimb using token
app.post('/api/reimbs/join', requireAuth, async (req, res) => {
  try {
    let { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    token = token.trim().toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/^(.{4})(.{4})$/, '$1-$2');

    const reimb = await Reimb.findOne({ token });
    if (!reimb) {
      return res.status(404).json({ error: 'Invalid token — no reimb found with this code' });
    }

    const email = req.user.email;
    if (reimb.ownerEmail === email) {
      return res.status(400).json({ error: 'You are the owner of this reimb' });
    }

    // Add viewer email if not already there
    if (!reimb.viewers.includes(email)) {
      reimb.viewers.push(email);
      await reimb.save();
    }

    res.json({
      id: reimb._id,
      name: reimb.name,
      token: reimb.token,
      owner_email: reimb.ownerEmail,
      role: 'viewer'
    });
  } catch (err) {
    console.error('Error joining reimb:', err);
    res.status(500).json({ error: 'Failed to join reimb: ' + err.message });
  }
});

// 4. Get expenses for a reimb (both accounts fetch this!)
app.get('/api/reimbs/:id/expenses', requireAuth, async (req, res) => {
  try {
    const reimbId = req.params.id;
    const email = req.user.email;

    // Check permission
    const reimb = await Reimb.findById(reimbId);
    if (!reimb || (reimb.ownerEmail !== email && !reimb.viewers.includes(email))) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const expenses = await Expense.find({ reimbId }).sort({ date: -1, createdAt: -1 });

    const formatted = expenses.map(e => ({
      id: e._id,
      amount: e.amount,
      category: e.category,
      date: e.date,
      note: e.note,
      by_email: e.byEmail,
      created_at: e.createdAt
    }));

    res.json(formatted);
  } catch (err) {
    console.error('Error getting expenses:', err);
    res.status(500).json({ error: 'Failed to load expenses: ' + err.message });
  }
});

// 5. Add expense (owner only)
app.post('/api/reimbs/:id/expenses', requireAuth, async (req, res) => {
  try {
    const reimbId = req.params.id;
    const { amount, category, date, note } = req.body;
    const email = req.user.email;

    if (!amount || isNaN(amount) || Number(amount) <= 0 || !category || !date) {
      return res.status(400).json({ error: 'Missing or invalid fields' });
    }

    const reimb = await Reimb.findById(reimbId);
    if (!reimb || reimb.ownerEmail !== email) {
      return res.status(403).json({ error: 'Only the owner can add expenses' });
    }

    const created = await Expense.create({
      reimbId,
      amount: Number(amount),
      category,
      date,
      note: (note || '').trim(),
      byEmail: email
    });

    res.status(201).json({
      id: created._id,
      amount: created.amount,
      category: created.category,
      date: created.date,
      note: created.note,
      by_email: created.byEmail,
      created_at: created.createdAt
    });
  } catch (err) {
    console.error('Error adding expense:', err);
    res.status(500).json({ error: 'Failed to save expense: ' + err.message });
  }
});

// 6. Delete expense (owner only)
app.delete('/api/expenses/:id', requireAuth, async (req, res) => {
  try {
    const expenseId = req.params.id;
    const email = req.user.email;

    const expense = await Expense.findById(expenseId);
    if (!expense) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    const reimb = await Reimb.findById(expense.reimbId);
    if (!reimb || reimb.ownerEmail !== email) {
      return res.status(403).json({ error: 'Not allowed to delete this expense' });
    }

    await Expense.findByIdAndDelete(expenseId);
    res.json({ success: true, id: expenseId });
  } catch (err) {
    console.error('Error deleting expense:', err);
    res.status(500).json({ error: 'Failed to delete expense: ' + err.message });
  }
});

// Frontend fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => console.log(`Server listening on port ${port}`));
