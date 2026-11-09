-- Pure PostgreSQL Schema on Render (Token & Email sync, zero OAuth/Firebase)

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
