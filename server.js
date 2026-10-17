require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const pino = require('pino');
const makeWASocket = require('@whiskeysockets/baileys').default;
const { useMultiFileAuthState, DisconnectReason, Browsers } = require('@whiskeysockets/baileys');

const log = pino({ level: process.env.LOG_LEVEL || 'info' });
const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = path.resolve(process.env.DATA_DIR || '.data');
const SESSION_DIR = path.resolve(process.env.WA_SESSION_DIR || 'sessions');
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
fs.mkdirSync(SESSION_DIR, { recursive: true, mode: 0o700 });

const sessionSecret = process.env.SESSION_SECRET || '';
if (sessionSecret.length < 32) {
  console.error('SESSION_SECRET must be at least 32 characters. Set it in .env before starting.');
  process.exit(1);
}
if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD.length < 12) {
  console.error('Set ADMIN_EMAIL and an ADMIN_PASSWORD of at least 12 characters in .env.');
  process.exit(1);
}

const db = new Database(path.join(DATA_DIR, 'platform.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS bot_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  phone_number TEXT,
  status TEXT NOT NULL DEFAULT 'disconnected',
  last_error TEXT,
  connected_at TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS plugins (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT,
  event TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const initialPlugins = [
  ['ping', 'Ping', 'Reply to .ping with a basic status message.'],
  ['uptime', 'Uptime', 'Reply to .uptime with worker uptime.']
];
const insertPlugin = db.prepare('INSERT OR IGNORE INTO plugins(id,name,description,enabled) VALUES(?,?,?,1)');
for (const p of initialPlugins) insertPlugin.run(...p);

function audit(userId, event, details = '') {
  db.prepare('INSERT INTO audit_log(user_id,event,details) VALUES(?,?,?)').run(userId || null, event, String(details).slice(0, 500));
}
function userSessionPath(userId) {
  // User IDs are generated UUIDs; never accept a filesystem path from the request.
  return path.join(SESSION_DIR, userId);
}
function safeUser(row) {
  return row ? { id: row.id, email: row.email, role: row.role } : null;
}

const existingAdmin = db.prepare('SELECT id FROM users WHERE email = ?').get(process.env.ADMIN_EMAIL.toLowerCase());
if (!existingAdmin) {
  const id = crypto.randomUUID();
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12);
  db.prepare('INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)').run(id, process.env.ADMIN_EMAIL.toLowerCase(), hash, 'admin');
  db.prepare('INSERT INTO bot_sessions(id,user_id,status) VALUES(?,?,?)').run(crypto.randomUUID(), id, 'disconnected');
  log.info('Created initial admin account from environment variables.');
}

if (process.env.TRUST_PROXY === 'true') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: null
}}}));
app.use(express.json({ limit: '20kb' }));
app.use(session({
  name: 'thenuva.sid',
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR, concurrentDB: true }),
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use('/api/pair', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: '1h' }));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Please sign in first.' });
  const user = db.prepare('SELECT id,email,role FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return req.session.destroy(() => res.status(401).json({ error: 'Session expired. Sign in again.' }));
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin permission required.' });
  next();
}
function csrfCheck(req, res, next) {
  // SameSite=Strict is the baseline; Origin validation adds protection for browser mutations.
  const origin = req.get('origin');
  if (origin) {
    const expected = `${req.protocol}://${req.get('host')}`;
    if (origin !== expected) return res.status(403).json({ error: 'Origin check failed.' });
  }
  next();
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'thenuva-web-platform' }));
app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id,email,role FROM users WHERE id=?').get(req.session.userId);
  res.json({ user: safeUser(user) });
});
app.post('/api/auth/login', csrfCheck, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!email || !password || email.length > 254 || password.length > 200) return res.status(400).json({ error: 'Enter a valid email and password.' });
  const allowed = String(process.env.ALLOWED_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (allowed.length && !allowed.includes(email)) return res.status(403).json({ error: 'This account is not allowed to sign in.' });
  const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  const ok = user && await bcrypt.compare(password, user.password_hash);
  if (!ok) { audit(null, 'login_failed', email); return res.status(401).json({ error: 'Invalid email or password.' }); }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not create login session.' });
    req.session.userId = user.id;
    audit(user.id, 'login', 'web dashboard');
    res.json({ user: safeUser(user) });
  });
});
app.post('/api/auth/logout', requireAuth, csrfCheck, (req, res) => {
  audit(req.user.id, 'logout');
  req.session.destroy(() => { res.clearCookie('thenuva.sid'); res.json({ ok: true }); });
});

const workers = new Map();
const workerStartedAt = new Map();
function getOwnedBot(userId) {
  return db.prepare('SELECT * FROM bot_sessions WHERE user_id=?').get(userId);
}
function setBotState(userId, status, error = null, phone = undefined) {
  db.prepare(`UPDATE bot_sessions SET status=?,last_error=?,phone_number=COALESCE(?,phone_number),updated_at=datetime('now'),connected_at=CASE WHEN ?='connected' THEN datetime('now') ELSE connected_at END WHERE user_id=?`)
    .run(status, error ? String(error).slice(0, 500) : null, phone === undefined ? null : phone, status, userId);
}
async function startWorker(userId, phone) {
  const old = workers.get(userId);
  if (old) { try { old.end(undefined); } catch {} workers.delete(userId); }
  const authDir = userSessionPath(userId);
  fs.mkdirSync(authDir, { recursive: true, mode: 0o700 });
  const { state, saveCreds } = await useMultiFileAuthState(authDir);
  const sock = makeWASocket({
    auth: state,
    printQRInTerminal: false,
    browser: Browsers.macOS('THENUVA X MD'),
    logger: log.child({ userId }),
    markOnlineOnConnect: false,
    syncFullHistory: false
  });
  workers.set(userId, sock);
  workerStartedAt.set(userId, Date.now());
  sock.ev.on('creds.update', saveCreds);
  sock.ev.on('connection.update', async update => {
    const { connection, lastDisconnect } = update;
    if (connection === 'open') {
      const ownNumber = sock.user?.id?.split(':')[0]?.split('@')[0] || phone;
      setBotState(userId, 'connected', null, ownNumber);
      audit(userId, 'whatsapp_connected', ownNumber || '');
      log.info({ userId }, 'WhatsApp connection opened');
    }
    if (connection === 'close') {
      const statusCode = lastDisconnect?.error?.output?.statusCode;
      workers.delete(userId);
      if (statusCode === DisconnectReason.loggedOut) {
        setBotState(userId, 'disconnected', 'WhatsApp logged out. Clear this session and pair again.');
        audit(userId, 'whatsapp_logged_out');
      } else {
        setBotState(userId, 'disconnected', 'Connection closed. Pair again or restart the worker.');
      }
    }
  });
  sock.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return;
    for (const message of messages) {
      if (!message.message || message.key.fromMe || message.key.remoteJid === 'status@broadcast') continue;
      const body = message.message.conversation || message.message.extendedTextMessage?.text || '';
      const cmd = body.trim().toLowerCase();
      const enabled = id => !!db.prepare('SELECT enabled FROM plugins WHERE id=?').get(id)?.enabled;
      try {
        if (cmd === '.ping' && enabled('ping')) await sock.sendMessage(message.key.remoteJid, { text: '🏓 Pong! THENUVA X MD is online.' }, { quoted: message });
        if (cmd === '.uptime' && enabled('uptime')) {
          const seconds = Math.floor((Date.now() - (workerStartedAt.get(userId) || Date.now())) / 1000);
          const mins = Math.floor(seconds / 60); const hrs = Math.floor(mins / 60); const days = Math.floor(hrs / 24);
          const formatted = `${days}d ${hrs % 24}h ${mins % 60}m ${seconds % 60}s`;
          await sock.sendMessage(message.key.remoteJid, { text: `⏱️ THENUVA X MD\nWorker uptime: ${formatted}` }, { quoted: message });
        }
      } catch (e) { log.error({ userId, err: e }, 'Plugin command failed'); }
    }
  });
  return sock;
}

app.get('/api/dashboard', requireAuth, (req, res) => {
  const bot = getOwnedBot(req.user.id);
  const plugins = db.prepare('SELECT id,name,description,enabled FROM plugins ORDER BY name').all().map(p => ({ ...p, enabled: !!p.enabled }));
  res.json({ bot, plugins, workerRunning: workers.has(req.user.id), workerUptimeSeconds: workers.has(req.user.id) ? Math.floor((Date.now() - (workerStartedAt.get(req.user.id) || Date.now())) / 1000) : 0 });
});
app.post('/api/pair', requireAuth, csrfCheck, async (req, res) => {
  const phone = String(req.body?.phone || '').replace(/[\s()+-]/g, '');
  if (!/^\d{8,15}$/.test(phone)) return res.status(400).json({ error: 'Enter a phone number with country code, digits only. Example: 94771234567' });
  const existing = getOwnedBot(req.user.id);
  if (existing?.status === 'connected') return res.status(409).json({ error: 'This account is already connected. Disconnect it before pairing again.' });
  try {
    setBotState(req.user.id, 'pairing', null, phone);
    const sock = await startWorker(req.user.id, phone);
    // Baileys requires a short initialization period before requesting the pairing code.
    await new Promise(resolve => setTimeout(resolve, 1200));
    if (sock.authState?.creds?.registered) return res.status(409).json({ error: 'A saved WhatsApp session already exists. Use the existing connection or reset the session first.' });
    const code = await sock.requestPairingCode(phone);
    audit(req.user.id, 'pair_code_requested', phone);
    res.json({ code: code.match(/.{1,4}/g)?.join('-') || code, phone, message: 'On WhatsApp, open Linked Devices → Link a Device → Link with phone number, then enter this code.' });
  } catch (error) {
    log.error({ userId: req.user.id, err: error }, 'Pair code request failed');
    setBotState(req.user.id, 'disconnected', error.message);
    res.status(500).json({ error: 'Could not generate a pairing code. Check the VPS logs and try again.' });
  }
});
app.post('/api/disconnect', requireAuth, csrfCheck, async (req, res) => {
  const sock = workers.get(req.user.id);
  if (sock) { try { sock.end(undefined); } catch {} workers.delete(req.user.id); }
  setBotState(req.user.id, 'disconnected', null);
  audit(req.user.id, 'whatsapp_disconnected');
  res.json({ ok: true, message: 'Worker stopped. Saved credentials remain on this VPS.' });
});
app.post('/api/plugins/:id/toggle', requireAuth, csrfCheck, (req, res) => {
  const id = String(req.params.id || '');
  const plugin = db.prepare('SELECT * FROM plugins WHERE id=?').get(id);
  if (!plugin) return res.status(404).json({ error: 'Plugin not found.' });
  const enabled = plugin.enabled ? 0 : 1;
  db.prepare("UPDATE plugins SET enabled=? WHERE id=?").run(enabled, id);
  audit(req.user.id, 'plugin_toggled', `${id}:${enabled ? 'enabled' : 'disabled'}`);
  res.json({ id, enabled: !!enabled });
});
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json({ users: db.prepare(`SELECT u.id,u.email,u.role,u.created_at,b.status,b.phone_number FROM users u LEFT JOIN bot_sessions b ON b.user_id=u.id ORDER BY u.created_at DESC LIMIT 200`).all() });
});
app.post('/api/admin/users', requireAuth, requireAdmin, csrfCheck, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12 || password.length > 200) return res.status(400).json({ error: 'Enter a valid email and a password of at least 12 characters.' });
  const id = crypto.randomUUID();
  try {
    db.prepare('INSERT INTO users(id,email,password_hash,role) VALUES(?,?,?,?)').run(id, email, await bcrypt.hash(password, 12), 'user');
    db.prepare('INSERT INTO bot_sessions(id,user_id,status) VALUES(?,?,?)').run(crypto.randomUUID(), id, 'disconnected');
    audit(req.user.id, 'user_created', email);
    res.status(201).json({ id, email, role: 'user' });
  } catch (e) {
    if (String(e.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'An account with that email already exists.' });
    res.status(500).json({ error: 'Could not create user.' });
  }
});

app.use('/api', (err, req, res, next) => {
  log.error({ err }, 'API error');
  res.status(500).json({ error: 'Unexpected server error.' });
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const server = app.listen(PORT, HOST, () => log.info(`THENUVA Web Platform listening on http://${HOST}:${PORT}`));
async function shutdown() {
  log.info('Shutting down...');
  server.close();
  for (const [userId, sock] of workers) { try { sock.end(undefined); } catch {} workers.delete(userId); }
  db.close();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
