const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Database ──
const db = new Database(path.join(__dirname, 'studyenergy.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password   TEXT    NOT NULL,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS daily_stats (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    date          TEXT    NOT NULL,
    energy        INTEGER DEFAULT 0,
    battery_earned INTEGER DEFAULT 0,
    bonus_applied  INTEGER DEFAULT 0,
    UNIQUE(user_id, date),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    type       TEXT    NOT NULL,
    points     INTEGER NOT NULL,
    date       TEXT    NOT NULL,
    created_at TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── Prepared statements ──
const stmts = {
  findUser:        db.prepare('SELECT * FROM users WHERE username = ?'),
  createUser:      db.prepare('INSERT INTO users (username, password) VALUES (?, ?)'),

  getDailyStats:   db.prepare('SELECT * FROM daily_stats WHERE user_id = ? AND date = ?'),
  upsertDaily:     db.prepare(`
    INSERT INTO daily_stats (user_id, date, energy, battery_earned, bonus_applied)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id, date)
    DO UPDATE SET energy = excluded.energy,
                  battery_earned = excluded.battery_earned,
                  bonus_applied = excluded.bonus_applied
  `),
  getYesterday:    db.prepare('SELECT * FROM daily_stats WHERE user_id = ? AND date = ?'),
  countBatteries:  db.prepare(`
    SELECT COALESCE(SUM(battery_earned), 0) AS earned,
           COALESCE(SUM(bonus_applied), 0)  AS used
    FROM daily_stats WHERE user_id = ?
  `),

  addLog:          db.prepare('INSERT INTO activity_log (user_id, type, points, date) VALUES (?, ?, ?, ?)'),
  getTodayLog:     db.prepare('SELECT id, type, points, created_at FROM activity_log WHERE user_id = ? AND date = ? ORDER BY id DESC'),
  getTotalEnergy:  db.prepare('SELECT COALESCE(SUM(points), 0) AS total FROM activity_log WHERE user_id = ?'),

  leaderboard:     db.prepare(`
    SELECT u.id, u.username,
           COALESCE(SUM(a.points), 0) AS total_energy,
           COALESCE(today.energy, 0) AS today_energy,
           COALESCE(bat.earned, 0) - COALESCE(bat.used, 0) AS batteries
    FROM users u
    LEFT JOIN activity_log a ON a.user_id = u.id
    LEFT JOIN daily_stats today ON today.user_id = u.id AND today.date = ?
    LEFT JOIN (
      SELECT user_id,
             SUM(battery_earned) AS earned,
             SUM(bonus_applied) AS used
      FROM daily_stats GROUP BY user_id
    ) bat ON bat.user_id = u.id
    GROUP BY u.id
    ORDER BY total_energy DESC
  `),
};

// ── Middleware ──
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'study-energy-secret-' + Math.random().toString(36).slice(2),
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function yesterdayStr() {
  const d = new Date();
  d.setDate(d.getDate() - 1);
  return d.toISOString().slice(0, 10);
}

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function ensureToday(userId) {
  const today = todayStr();
  let stats = stmts.getDailyStats.get(userId, today);

  if (!stats) {
    const yesterday = stmts.getYesterday.get(userId, yesterdayStr());
    let bonusApplied = 0;

    if (yesterday && yesterday.battery_earned) {
      const batRow = stmts.countBatteries.get(userId);
      const available = batRow.earned - batRow.used;
      if (available > 0) {
        bonusApplied = 1;
      }
    }

    const startEnergy = bonusApplied ? 20 : 0;
    stmts.upsertDaily.run(userId, today, startEnergy, 0, bonusApplied);

    if (bonusApplied) {
      stmts.addLog.run(userId, 'Battery Bonus', 20, today);
    }

    stats = stmts.getDailyStats.get(userId, today);
  }

  return stats;
}

// ── Auth routes ──
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length > 22) return res.status(400).json({ error: 'Username too long (max 22 chars)' });
  if (password.length < 3) return res.status(400).json({ error: 'Password too short (min 3 chars)' });

  const existing = stmts.findUser.get(username);
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const result = stmts.createUser.run(username, hash);

  req.session.userId = result.lastInsertRowid;
  req.session.username = username;

  res.json({ ok: true, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = stmts.findUser.get(username);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;

  res.json({ ok: true, username: user.username });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ── Data routes ──
app.get('/api/me', requireAuth, (req, res) => {
  const dailyStats = ensureToday(req.session.userId);
  const totalRow = stmts.getTotalEnergy.get(req.session.userId);
  const batRow = stmts.countBatteries.get(req.session.userId);

  res.json({
    username:    req.session.username,
    totalEnergy: totalRow.total,
    todayEnergy: dailyStats.energy,
    batteries:   batRow.earned - batRow.used,
    batEarned:   !!dailyStats.battery_earned,
    bonusActive: !!dailyStats.bonus_applied,
  });
});

app.post('/api/log', requireAuth, (req, res) => {
  const { type, points } = req.body;
  if (!type || points === undefined) return res.status(400).json({ error: 'type and points required' });

  const userId = req.session.userId;
  const today = todayStr();
  const BAT_GOAL = 65;

  ensureToday(userId);

  const logResult = stmts.addLog.run(userId, type, points, today);

  const stats = stmts.getDailyStats.get(userId, today);
  const newEnergy = Math.max(0, stats.energy + points);
  let batEarned = stats.battery_earned;

  if (newEnergy >= BAT_GOAL && !batEarned) {
    batEarned = 1;
  }

  stmts.upsertDaily.run(userId, today, newEnergy, batEarned, stats.bonus_applied);

  const totalRow = stmts.getTotalEnergy.get(userId);
  const batRow = stmts.countBatteries.get(userId);
  const updatedStats = stmts.getDailyStats.get(userId, today);

  res.json({
    id:          logResult.lastInsertRowid,
    totalEnergy: totalRow.total,
    todayEnergy: updatedStats.energy,
    batteries:   batRow.earned - batRow.used,
    batEarned:   !!updatedStats.battery_earned,
    newBattery:  !stats.battery_earned && !!updatedStats.battery_earned,
  });
});

app.get('/api/history', requireAuth, (req, res) => {
  const logs = stmts.getTodayLog.all(req.session.userId, todayStr());
  res.json(logs);
});

app.get('/api/leaderboard', (req, res) => {
  res.json(stmts.leaderboard.all(todayStr()));
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));

app.listen(PORT, () => console.log(`Study Energy running at http://localhost:${PORT}`));
