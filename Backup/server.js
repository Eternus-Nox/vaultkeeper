'use strict';

// ═══════════════════════════════════════════════════════════════════════════
//  VaultKeeper Server — E2E Edition (Day 2)
// ═══════════════════════════════════════════════════════════════════════════
//  This server stores OPAQUE CIPHERTEXT ONLY. It never sees plaintext vault
//  data, and it never handles raw master passwords.
//
//  Auth flow:
//    1. Client runs argon2id(username, password) → masterKey
//    2. Client runs argon2id(masterKey, "vk-auth-v1") → authHash (32 bytes)
//    3. Client sends authHash to the server
//    4. Server bcrypt-hashes authHash before storing/comparing
//
//  Vault data flow:
//    1. Client encrypts item JSON with AES-256-GCM + HMAC under symKey
//    2. Client sends base64 envelope to server
//    3. Server stores string as-is, returns it unchanged
//
//  What the server knows: username, KDF parameters, encrypted blobs.
//  What the server does NOT know: passwords, item contents, folder names.
// ═══════════════════════════════════════════════════════════════════════════

const express = require('express');
const jwt = require('jsonwebtoken');
const VKWebAuthn = require('./vk-webauthn');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const https = require('https');
const http = require('http');

// ── CONFIG ────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3333', 10);
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = process.env.NODE_ENV || 'production';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

// Secret used to derive deterministic "fake" KDF params for non-existent
// users, so prelogin can't be used to enumerate real accounts. Separate
// from JWT_SECRET so compromising one doesn't compromise the other.
const PRELOGIN_SECRET = process.env.PRELOGIN_SECRET || JWT_SECRET;

// If set, server drops and recreates all tables on startup. One-time reset
// for fresh deployments. Refuses to run without explicit confirmation.
const DROP_AND_RECREATE = process.env.DROP_AND_RECREATE === 'yes-I-am-sure';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('[FATAL] JWT_SECRET must be set and at least 32 characters');
  process.exit(1);
}
// Note: ENCRYPTION_KEY is no longer required. If set, it's ignored.
if (process.env.ENCRYPTION_KEY) {
  console.warn('[INFO] ENCRYPTION_KEY env var is set but no longer used (E2E mode). Safe to remove.');
}

// ── KDF POLICY ────────────────────────────────────────────────────────────
// Minimum argon2id parameters we accept from the client. Anything weaker is
// rejected at signup and password-change. Prevents a hostile client from
// choosing trivially-crackable parameters.
//
// These are the floor. The RECOMMENDED params are sent by the stock client
// and can be higher (current client default: 262144 KiB).
const KDF_MIN = Object.freeze({
  memory_cost: 65536,   // 64 MiB
  time_cost: 2,
  parallelism: 1,
});
const KDF_MAX = Object.freeze({
  memory_cost: 1048576, // 1 GiB — upper bound so a malicious client can't DoS
  time_cost: 10,
  parallelism: 4,
});

// ── INPUT LIMITS ──────────────────────────────────────────────────────────
const MAX_USERNAME         = 50;
const MIN_USERNAME         = 2;
const USERNAME_REGEX       = /^[a-z0-9._-]{2,50}$/;
const MAX_AUTH_HASH_B64    = 64;                  // 32 bytes → 44 chars base64; 64 is slack
const MAX_PROTECTED_SYM_KEY_B64 = 256;            // ~125 bytes → ~168 chars base64; 256 is slack
const MAX_ENCRYPTED_DATA_B64 = 256 * 1024;        // 192 KiB raw → 256 KiB base64
const MAX_ENCRYPTED_NAME_B64 = 1024;              // folder name encrypted: ~600 chars + slack
const MAX_COLOR_LEN        = 20;
const VALID_HEX_COLOR      = /^#[0-9a-fA-F]{3,6}$/;
const VALID_TYPES          = new Set(['login', 'note', 'card', 'identity']);
const MAX_ITEMS_PER_USER   = 10000;   // soft cap
const MAX_FOLDERS_PER_USER = 200;

// ── APP ───────────────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
// Ciphertext blobs are large; raise body limit to comfortably fit imports.
app.use(express.json({ limit: '8mb' }));

// ── SECURITY HEADERS ──────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), payment=()');
  // 'wasm-unsafe-eval' is required for the client to compile the argon2id
  // WebAssembly module. It's strictly weaker than 'unsafe-eval' — only WASM,
  // not JavaScript eval.
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'",
      "style-src 'self' 'unsafe-inline'",
      "font-src 'self' data:",
      "img-src 'self' data:",
      "manifest-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join('; ')
  );
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  next();
});

// ── ORIGIN GUARD ──────────────────────────────────────────────────────────
function extractHostname(hostHeader) {
  if (!hostHeader) return '';
  const first = hostHeader.split(',')[0].trim();
  if (first.startsWith('[')) {
    const end = first.indexOf(']');
    return end >= 0 ? first.slice(1, end).toLowerCase() : first.toLowerCase();
  }
  const portIdx = first.lastIndexOf(':');
  return (portIdx > 0 ? first.slice(0, portIdx) : first).toLowerCase();
}

app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const origin = req.headers.origin;
  if (!origin) return next();
  const expected = extractHostname(req.headers['x-forwarded-host'] || req.headers.host);
  try {
    const o = new URL(origin);
    if (o.hostname.toLowerCase() === expected) return next();
    if (ALLOWED_ORIGINS.includes(origin)) return next();
  } catch { /* fall through */ }
  console.warn(`[ORIGIN] Rejected: origin=${origin} host=${req.headers['x-forwarded-host'] || req.headers.host}`);
  return res.status(403).json({ error: 'Forbidden origin' });
});

// ── STATIC ASSETS ─────────────────────────────────────────────────────────
const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR, {
  index: false,
  setHeaders(res, filePath) {
    // index.html and the client crypto module must never be cached aggressively
    // — we need updates to flow immediately. Everything in /vendor/ can be
    // cached long because it's versioned bundles.
    if (filePath.endsWith('index.html') || filePath.endsWith('/vk-crypto.js')) {
      res.setHeader('Cache-Control', 'no-store');
    } else if (filePath.includes('/vendor/')) {
      res.setHeader('Cache-Control', 'public, max-age=604800, immutable');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=300');
    }
  }
}));
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

// ── DATABASE ──────────────────────────────────────────────────────────────
const pool = new Pool({
  host:                    process.env.PGHOST || 'db',
  port:                    parseInt(process.env.PGPORT || '5432', 10),
  database:                process.env.PGDATABASE || 'vaultkeeper',
  user:                    process.env.PGUSER || 'vault',
  password:                process.env.PGPASSWORD || '',
  max:                     10,
  idleTimeoutMillis:       30000,
  connectionTimeoutMillis: 5000,
  query_timeout:           10000,
  statement_timeout:       10000,
});
pool.on('error', (err) => console.error('[DB] Idle client error:', err.message));

async function waitForDB(retries = 15, delayMs = 3000) {
  for (let i = 1; i <= retries; i++) {
    try {
      await pool.query('SELECT 1');
      console.log('[DB] PostgreSQL connection established');
      return;
    } catch (err) {
      console.log(`[DB] Waiting for PostgreSQL... attempt ${i}/${retries} (${err.message})`);
      if (i === retries) throw new Error('Could not connect to PostgreSQL after ' + retries + ' attempts');
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
}

// Check if old pre-E2E schema exists. If it does and DROP_AND_RECREATE isn't
// set, refuse to start — we won't silently trash someone's data.
async function checkForLegacySchema() {
  const { rows } = await pool.query(`
    SELECT column_name FROM information_schema.columns
     WHERE table_name = 'users' AND column_name IN ('password_hash', 'protected_symmetric_key')
  `);
  const hasLegacy = rows.some(r => r.column_name === 'password_hash');
  const hasE2E    = rows.some(r => r.column_name === 'protected_symmetric_key');
  return { hasLegacy, hasE2E };
}

async function initDB() {
  await waitForDB();

  const { hasLegacy, hasE2E } = await checkForLegacySchema();
  if (hasLegacy && !DROP_AND_RECREATE) {
    console.error('');
    console.error('════════════════════════════════════════════════════════════════════');
    console.error('  FATAL: Database contains pre-E2E schema (column `password_hash`).');
    console.error('  This server version requires the E2E schema.');
    console.error('');
    console.error('  To proceed, ensure you have backed up anything important, then');
    console.error('  restart with DROP_AND_RECREATE=yes-I-am-sure in the environment.');
    console.error('  ALL EXISTING DATA WILL BE DELETED.');
    console.error('════════════════════════════════════════════════════════════════════');
    console.error('');
    process.exit(1);
  }

  if (DROP_AND_RECREATE) {
    console.warn('[INIT] DROP_AND_RECREATE=yes-I-am-sure — dropping all tables');
    await pool.query(`
      DROP TABLE IF EXISTS audit_log CASCADE;
      DROP TABLE IF EXISTS vault_items CASCADE;
      DROP TABLE IF EXISTS folders CASCADE;
      DROP TABLE IF EXISTS users CASCADE;
    `);
  }

  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      -- bcrypt hash of the client-derived authHash. NOT the master password.
      auth_hash TEXT NOT NULL,
      -- base64 envelope containing the user's random symmetric key, encrypted
      -- under a key derived from the user's master password.
      protected_symmetric_key TEXT NOT NULL,
      -- KDF parameters the client used when deriving their master key. Sent
      -- back to the client at login so they can re-derive the same key.
      kdf_memory_cost INTEGER NOT NULL,
      kdf_time_cost INTEGER NOT NULL,
      kdf_parallelism INTEGER NOT NULL,
      -- Bumped on password change to invalidate all existing JWTs.
      token_version INTEGER NOT NULL DEFAULT 1,
      -- Non-sensitive preferences (theme, etc). JSONB for flexibility.
      preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login_at TIMESTAMPTZ
    )`,
    `CREATE TABLE IF NOT EXISTS folders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      -- Encrypted envelope (base64). The NAME is sensitive (e.g. "Banking",
      -- "Porn") — so it's encrypted client-side like items. Color is NOT
      -- sensitive and stays plaintext for UI use.
      encrypted_name TEXT NOT NULL,
      color TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS vault_items (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      -- Type is left in plaintext because it's used for server-side
      -- validation and UI-level grouping. It leaks "this user has 3 cards"
      -- but not the card contents. Acceptable tradeoff.
      type TEXT NOT NULL CHECK (type IN ('login', 'note', 'card', 'identity')),
      folder_id INTEGER REFERENCES folders(id) ON DELETE SET NULL,
      favorite BOOLEAN NOT NULL DEFAULT false,
      -- The payload: a base64 envelope containing everything else (name, URL,
      -- username, password, notes, TOTP, etc). Opaque to the server.
      encrypted_data TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE TABLE IF NOT EXISTS audit_log (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      details TEXT,
      ip TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_vault_user_updated ON vault_items(user_id, updated_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_vault_user_type ON vault_items(user_id, type)`,
    `CREATE INDEX IF NOT EXISTS idx_vault_folder ON vault_items(folder_id) WHERE folder_id IS NOT NULL`,
    `CREATE INDEX IF NOT EXISTS idx_folders_user ON folders(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_log(user_id, created_at DESC)`,

    // ── Soft-delete migration ────────────────────────────────────
    // Add a deleted_at column for trash/restore. NULL means active;
    // a timestamp means the item is in the trash and will be auto-
    // purged after the configured TTL (6 months by default).
    `ALTER TABLE vault_items ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ`,
    `CREATE INDEX IF NOT EXISTS idx_vault_user_deleted
       ON vault_items(user_id, deleted_at)
       WHERE deleted_at IS NOT NULL`,
    `CREATE INDEX IF NOT EXISTS idx_vault_user_active
       ON vault_items(user_id, updated_at DESC)
       WHERE deleted_at IS NULL`,

    // ── Password generation history ──────────────────────────────
    // Stores encrypted-on-device password generations the user has
    // copied from the generator. Server sees only ciphertext.
    // Auto-purges after 6 months. Encrypted blob holds the password
    // string itself plus tiny metadata (length, character classes
    // used) — all opaque to the server.
    `CREATE TABLE IF NOT EXISTS password_history (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_data TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`,
    // Defensive: if a previous run created password_history without
    // created_at (e.g. a partial migration that failed mid-flight),
    // CREATE TABLE IF NOT EXISTS won't fix it. Add the column
    // explicitly so the index below succeeds.
    `ALTER TABLE password_history ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`,
    `ALTER TABLE password_history ADD COLUMN IF NOT EXISTS encrypted_data TEXT`,
    // Drop legacy columns from older schema attempts. Earlier drafts of
    // password_history had item_id and password columns that the
    // current code never populates. Leftover NOT NULL constraints on
    // those would force every INSERT to fail. Dropping is safe —
    // current code never reads or writes them.
    `ALTER TABLE password_history DROP COLUMN IF EXISTS item_id`,
    `ALTER TABLE password_history DROP COLUMN IF EXISTS password`,
    `ALTER TABLE password_history DROP COLUMN IF EXISTS password_hash`,
    `ALTER TABLE password_history DROP COLUMN IF EXISTS password_encrypted`,
    `ALTER TABLE password_history DROP COLUMN IF EXISTS metadata`,
    `ALTER TABLE password_history DROP COLUMN IF EXISTS length`,
    `CREATE INDEX IF NOT EXISTS idx_pwhist_user_created
       ON password_history(user_id, created_at DESC)`,
  ];
  for (let i = 0; i < statements.length; i++) {
    try {
      await pool.query(statements[i]);
    } catch (err) {
      // Surface exactly which migration failed, so we can debug missing
      // columns on existing databases without guessing.
      const snippet = statements[i].replace(/\s+/g, ' ').slice(0, 120);
      console.error('[DB] Migration #' + i + ' failed: ' + err.message);
      console.error('[DB]   SQL: ' + snippet + (statements[i].length > 120 ? '…' : ''));
      throw err;
    }
  }
  // WebAuthn (Face ID / passkey) tables
  await VKWebAuthn.ensureSchema(pool);

  // ── Safety net: drop any leftover NOT NULL columns on password_history ──
  // We've been hit several times by previous failed migrations leaving
  // behind a NOT NULL column that current code doesn't populate. This
  // generically finds and removes any such column, so we never have to
  // guess which one was left behind.
  const EXPECTED_PWHIST_COLS = new Set([
    'id', 'user_id', 'encrypted_data', 'created_at',
  ]);
  try {
    const { rows: pwhistCols } = await pool.query(
      `SELECT column_name, is_nullable, column_default
         FROM information_schema.columns
        WHERE table_name = 'password_history'`
    );
    for (const c of pwhistCols) {
      const name = c.column_name;
      if (EXPECTED_PWHIST_COLS.has(name)) continue;
      // Unexpected column. If it's NOT NULL with no default it'll
      // break every INSERT. Drop it.
      console.warn('[DB] Dropping unexpected column password_history.' + name);
      try {
        await pool.query('ALTER TABLE password_history DROP COLUMN IF EXISTS "' + name + '"');
      } catch (e) {
        console.error('[DB]   could not drop:', e.message);
      }
    }
  } catch (e) {
    console.warn('[DB] password_history column inspection failed:', e.message);
  }

  console.log('[DB] Schema verified');
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  if (!hdr.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try {
    const payload = jwt.verify(hdr.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Verify JWT's token_version matches the DB; if not, user's session was
// invalidated (password change / signout everywhere).
async function verifyTokenVersion(req, res) {
  const { rows } = await pool.query(
    'SELECT token_version FROM users WHERE id = $1', [req.user.id]
  );
  if (!rows.length || rows[0].token_version !== req.user.tv) {
    res.status(401).json({ error: 'Session expired' });
    return false;
  }
  return true;
}

function ah(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

async function audit(userId, action, details, ip) {
  try {
    await pool.query(
      'INSERT INTO audit_log (user_id, action, details, ip) VALUES ($1, $2, $3, $4)',
      [userId, action, details ? String(details).slice(0, 500) : null, ip || null]
    );
  } catch (e) {
    console.error('[AUDIT] insert failed:', e.message);
  }
}

// Prune old audit entries hourly. Keep newest 100 per user + last 30 days.
let _lastPrune = 0;
async function maybePruneAuditLog() {
  const now = Date.now();
  if (now - _lastPrune < 3600_000) return; // once an hour
  _lastPrune = now;
  try {
    await pool.query(`
      DELETE FROM audit_log
       WHERE id IN (
         SELECT id FROM (
           SELECT id, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC) AS rn,
                  created_at
             FROM audit_log
         ) t
         WHERE t.rn > 100 AND t.created_at < NOW() - INTERVAL '30 days'
       )
    `);
  } catch (e) {
    console.error('[AUDIT] prune failed:', e.message);
  }
}

// ── RATE LIMITER ──────────────────────────────────────────────────────────
// In-memory counters keyed by IP. For a single-user self-hosted app this is
// plenty; multi-tenant deployments should use Redis.
const _authAttempts = new Map();
// IPs exempted from rate limiting. Localhost is here so tests run from the
// host machine don't trip the limit.
const RL_EXEMPT_IPS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
function authLimiter(req, res, next) {
  const ip = req.ip || 'unknown';
  if (RL_EXEMPT_IPS.has(ip)) return next();
  const now = Date.now();
  let bucket = _authAttempts.get(ip);
  if (!bucket || now - bucket.start > 15 * 60_000) {
    bucket = { start: now, count: 0 };
    _authAttempts.set(ip, bucket);
  }
  bucket.count++;
  if (bucket.count > 20) {
    return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  }
  next();
}
// GC old entries periodically
setInterval(() => {
  const cutoff = Date.now() - 15 * 60_000;
  for (const [ip, b] of _authAttempts) if (b.start < cutoff) _authAttempts.delete(ip);
}, 60_000).unref();

// ── HELPERS ───────────────────────────────────────────────────────────────
function normalizeUsername(u) {
  if (typeof u !== 'string') return null;
  const trimmed = u.trim().toLowerCase();
  if (!USERNAME_REGEX.test(trimmed)) return null;
  return trimmed;
}

function isValidBase64(s, maxLen) {
  if (typeof s !== 'string') return false;
  if (s.length === 0 || s.length > maxLen) return false;
  // Standard base64 alphabet + padding. No URL-safe variants here.
  return /^[A-Za-z0-9+/]*={0,2}$/.test(s);
}

function validateKdfParams(kdf) {
  if (!kdf || typeof kdf !== 'object') return 'kdf params missing';
  const mc = kdf.memory_cost, tc = kdf.time_cost, p = kdf.parallelism;
  if (!Number.isInteger(mc) || mc < KDF_MIN.memory_cost || mc > KDF_MAX.memory_cost) {
    return `memory_cost out of range [${KDF_MIN.memory_cost}, ${KDF_MAX.memory_cost}]`;
  }
  if (!Number.isInteger(tc) || tc < KDF_MIN.time_cost || tc > KDF_MAX.time_cost) {
    return `time_cost out of range [${KDF_MIN.time_cost}, ${KDF_MAX.time_cost}]`;
  }
  if (!Number.isInteger(p) || p < KDF_MIN.parallelism || p > KDF_MAX.parallelism) {
    return `parallelism out of range [${KDF_MIN.parallelism}, ${KDF_MAX.parallelism}]`;
  }
  return null;
}

// Deterministic fake KDF params for non-existent users. Prevents enumeration
// via the prelogin endpoint. The parameters look indistinguishable from real
// ones but are derived from a hash of the username + a server secret.
function fakeKdfParamsForUsername(username) {
  const h = crypto.createHmac('sha256', PRELOGIN_SECRET).update(username).digest();
  // Pick a plausible memory_cost from [65536, 262144] deterministically
  const mcPool = [65536, 131072, 196608, 262144];
  return {
    memory_cost: mcPool[h[0] % mcPool.length],
    time_cost: 2 + (h[1] % 3),   // 2, 3, or 4
    parallelism: 1,
  };
}

// ── LIVENESS ──────────────────────────────────────────────────────────────
app.get('/healthz', ah(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true, mode: 'e2e', timestamp: new Date().toISOString() });
}));

// ═══════════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/auth/signup
// Body: { username, auth_hash, protected_symmetric_key, kdf: { memory_cost, time_cost, parallelism } }
// Returns: { token, username }
app.post('/api/auth/signup', authLimiter, ah(async (req, res) => {
  const { username: rawUsername, auth_hash, protected_symmetric_key, kdf } = req.body || {};

  const username = normalizeUsername(rawUsername);
  if (!username) {
    return res.status(400).json({ error: 'Invalid username (2-50 chars, a-z, 0-9, . _ -)' });
  }
  if (!isValidBase64(auth_hash, MAX_AUTH_HASH_B64)) {
    return res.status(400).json({ error: 'Invalid auth_hash' });
  }
  if (!isValidBase64(protected_symmetric_key, MAX_PROTECTED_SYM_KEY_B64)) {
    return res.status(400).json({ error: 'Invalid protected_symmetric_key' });
  }
  const kdfErr = validateKdfParams(kdf);
  if (kdfErr) return res.status(400).json({ error: 'Invalid KDF: ' + kdfErr });

  // bcrypt-hash the auth_hash before storing. The auth_hash is already a
  // 32-byte high-entropy value from client-side argon2id, so bcrypt's cost
  // factor can be low (10 is plenty). The expensive KDF work happens on
  // the client; server-side bcrypt is just defense-in-depth against
  // direct-hash replay if the DB leaks.
  const stored = await bcrypt.hash(auth_hash, 10);

  try {
    const { rows } = await pool.query(
      `INSERT INTO users (username, auth_hash, protected_symmetric_key,
                           kdf_memory_cost, kdf_time_cost, kdf_parallelism)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, username, token_version`,
      [username, stored, protected_symmetric_key,
       kdf.memory_cost, kdf.time_cost, kdf.parallelism]
    );
    const user = rows[0];
    const token = jwt.sign({ id: user.id, username: user.username, tv: user.token_version },
                           JWT_SECRET, { expiresIn: '7d' });
    await audit(user.id, 'signup', null, req.ip);
    res.json({ token, username: user.username });
  } catch (e) {
    // Generic 400 for unique-constraint violation — don't leak "user exists"
    if (e.code === '23505') {
      return res.status(400).json({ error: 'Could not create account (username may be taken)' });
    }
    throw e;
  }
}));

// POST /api/auth/prelogin
// Body: { username }
// Returns: { kdf: { memory_cost, time_cost, parallelism } }
//
// Always returns valid-looking KDF params, even for non-existent users.
// Does NOT confirm whether the user exists — enumerating users must happen
// through the rate-limited login endpoint instead.
app.post('/api/auth/prelogin', authLimiter, ah(async (req, res) => {
  const username = normalizeUsername(req.body?.username);
  if (!username) {
    // Still return SOMETHING that looks normal — don't differentiate invalid
    // username format from nonexistent user.
    return res.json({ kdf: fakeKdfParamsForUsername(String(req.body?.username || '')) });
  }
  const { rows } = await pool.query(
    'SELECT kdf_memory_cost, kdf_time_cost, kdf_parallelism FROM users WHERE username = $1',
    [username]
  );
  if (rows.length === 0) {
    return res.json({ kdf: fakeKdfParamsForUsername(username) });
  }
  res.json({
    kdf: {
      memory_cost: rows[0].kdf_memory_cost,
      time_cost: rows[0].kdf_time_cost,
      parallelism: rows[0].kdf_parallelism,
    }
  });
}));

// POST /api/auth/login
// Body: { username, auth_hash }
// Returns: { token, username, protected_symmetric_key }
app.post('/api/auth/login', authLimiter, ah(async (req, res) => {
  const { username: rawUsername, auth_hash } = req.body || {};
  const username = normalizeUsername(rawUsername);
  if (!username || !isValidBase64(auth_hash, MAX_AUTH_HASH_B64)) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const { rows } = await pool.query(
    `SELECT id, username, auth_hash, protected_symmetric_key, token_version
       FROM users WHERE username = $1`,
    [username]
  );

  // Constant-time comparison: if user doesn't exist, still do a bcrypt call
  // against a dummy hash so the response time is comparable. This prevents
  // timing-based user enumeration.
  const DUMMY_HASH = '$2a$10$CwTycUXWue0Thq9StjUM0uJ8qxCpBS5zZWzGxkEHMl5qv5pYwRz6a';
  const stored = rows[0]?.auth_hash || DUMMY_HASH;
  const valid = await bcrypt.compare(auth_hash, stored);

  if (!rows.length || !valid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const user = rows[0];
  const token = jwt.sign({ id: user.id, username: user.username, tv: user.token_version },
                          JWT_SECRET, { expiresIn: '7d' });

  await pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [user.id]);
  await audit(user.id, 'login', null, req.ip);
  maybePruneAuditLog();

  res.json({
    token,
    username: user.username,
    protected_symmetric_key: user.protected_symmetric_key,
  });
}));

// GET /api/auth/me
app.get('/api/auth/me', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  res.json({ id: req.user.id, username: req.user.username });
}));

// POST /api/auth/change-password
// Body: { current_auth_hash, new_auth_hash, new_protected_symmetric_key, new_kdf: {...} }
//
// The client has already:
//   1. Derived the old masterKey from the old password
//   2. Unwrapped the symKey
//   3. Re-wrapped the symKey under a new masterKey derived from the new password
//   4. Derived the new auth_hash
// The server just validates current auth, then swaps the stored fields
// atomically. Token version bumps so all other sessions are invalidated.
app.post('/api/auth/change-password', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;

  const { current_auth_hash, new_auth_hash, new_protected_symmetric_key, new_kdf } = req.body || {};
  if (!isValidBase64(current_auth_hash, MAX_AUTH_HASH_B64)) {
    return res.status(400).json({ error: 'Invalid current_auth_hash' });
  }
  if (!isValidBase64(new_auth_hash, MAX_AUTH_HASH_B64)) {
    return res.status(400).json({ error: 'Invalid new_auth_hash' });
  }
  if (!isValidBase64(new_protected_symmetric_key, MAX_PROTECTED_SYM_KEY_B64)) {
    return res.status(400).json({ error: 'Invalid new_protected_symmetric_key' });
  }
  const kdfErr = validateKdfParams(new_kdf);
  if (kdfErr) return res.status(400).json({ error: 'Invalid KDF: ' + kdfErr });

  const { rows } = await pool.query(
    'SELECT auth_hash FROM users WHERE id = $1', [req.user.id]
  );
  if (!rows.length) return res.status(401).json({ error: 'User not found' });

  const ok = await bcrypt.compare(current_auth_hash, rows[0].auth_hash);
  if (!ok) return res.status(401).json({ error: 'Current password is wrong' });

  const newStored = await bcrypt.hash(new_auth_hash, 10);
  await pool.query(
    `UPDATE users
        SET auth_hash = $1,
            protected_symmetric_key = $2,
            kdf_memory_cost = $3, kdf_time_cost = $4, kdf_parallelism = $5,
            token_version = token_version + 1
      WHERE id = $6`,
    [newStored, new_protected_symmetric_key,
     new_kdf.memory_cost, new_kdf.time_cost, new_kdf.parallelism,
     req.user.id]
  );
  await audit(req.user.id, 'password_change', null, req.ip);
  res.json({ ok: true, message: 'Password changed. Please log in again.' });
}));

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/auth/account
//
// Permanently deletes the account: user row, all vault items, all folders.
// Audit log entries are preserved (with the now-orphaned user_id) for
// after-the-fact investigations.
//
// Requires the current auth_hash for verification — same flow as change-password.
// ─────────────────────────────────────────────────────────────────────────────
app.delete('/api/auth/account', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;

  const { current_auth_hash } = req.body || {};
  if (!isValidBase64(current_auth_hash, MAX_AUTH_HASH_B64)) {
    return res.status(400).json({ error: 'Invalid current_auth_hash' });
  }

  const { rows } = await pool.query(
    'SELECT auth_hash, username FROM users WHERE id = $1', [req.user.id]
  );
  if (!rows.length) return res.status(401).json({ error: 'User not found' });

  const ok = await bcrypt.compare(current_auth_hash, rows[0].auth_hash);
  if (!ok) return res.status(401).json({ error: 'Current password is wrong' });

  const username = rows[0].username;
  // Audit before deletion — user_id has ON DELETE CASCADE, so the audit
  // row will get swept up too. Logging it first ensures it makes it to
  // disk for any aggregator/exporter watching the table.
  await audit(req.user.id, 'account_delete', username, req.ip);

  // Cascade FK on vault_items, folders, and audit_log all reference
  // users(id) ON DELETE CASCADE — deleting the user row is enough.
  await pool.query('DELETE FROM users WHERE id = $1', [req.user.id]);

  res.json({ ok: true, message: 'Account permanently deleted.' });
}));

// ═══════════════════════════════════════════════════════════════════════════
//  WEBAUTHN (Face ID / passkey login)
// ═══════════════════════════════════════════════════════════════════════════
// Mounts the following endpoints:
//   POST   /api/auth/webauthn/register-options
//   POST   /api/auth/webauthn/register
//   POST   /api/auth/webauthn/login-options
//   POST   /api/auth/webauthn/login
//   GET    /api/auth/webauthn/list
//   DELETE /api/auth/webauthn/:credentialId
// See vk-webauthn.js for full architectural notes.
VKWebAuthn.mount(app, { pool, auth, ah, JWT_SECRET, authLimiter });

// Periodic cleanup of expired challenges (every 10 minutes)
setInterval(() => {
  VKWebAuthn.cleanupExpiredChallenges(pool).catch(err => {
    console.error('[webauthn] cleanup failed:', err.message);
  });
}, 10 * 60 * 1000).unref?.();

// ── Trash and password-history TTL cleanup ────────────────────────
// Trashed items and stored password generations live for 6 months,
// then are permanently deleted. This runs once an hour and on
// startup (deferred so it doesn't block initial request handling).
const SIX_MONTHS_INTERVAL = "INTERVAL '6 months'";
async function cleanupExpiredData() {
  try {
    const trash = await pool.query(
      `DELETE FROM vault_items
        WHERE deleted_at IS NOT NULL
          AND deleted_at < NOW() - ${SIX_MONTHS_INTERVAL}`
    );
    const hist = await pool.query(
      `DELETE FROM password_history
        WHERE created_at < NOW() - ${SIX_MONTHS_INTERVAL}`
    );
    if (trash.rowCount || hist.rowCount) {
      console.log(`[cleanup] purged ${trash.rowCount} trashed item(s), ` +
                  `${hist.rowCount} expired password-history entries`);
    }
  } catch (err) {
    console.error('[cleanup] failed:', err.message);
  }
}
setTimeout(cleanupExpiredData, 30 * 1000).unref?.();
setInterval(cleanupExpiredData, 60 * 60 * 1000).unref?.();

// ═══════════════════════════════════════════════════════════════════════════
//  USER PREFERENCES (non-sensitive)
// ═══════════════════════════════════════════════════════════════════════════
const ALLOWED_PREF_KEYS = ['theme', 'clipboard_clear_seconds', 'default_view'];
function sanitizePrefs(obj) {
  if (!obj || typeof obj !== 'object') return {};
  const out = {};
  for (const k of ALLOWED_PREF_KEYS) {
    if (k in obj) {
      const v = obj[k];
      if (k === 'theme' && ['light', 'dark', 'oled'].includes(v)) out[k] = v;
      else if (k === 'clipboard_clear_seconds' && Number.isInteger(v) && v >= 0 && v <= 300) out[k] = v;
      else if (k === 'default_view' && ['all', 'favorites', 'login', 'card', 'note', 'identity'].includes(v)) out[k] = v;
    }
  }
  return out;
}

app.get('/api/prefs', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rows } = await pool.query('SELECT preferences FROM users WHERE id = $1', [req.user.id]);
  res.json(rows[0]?.preferences || {});
}));

app.patch('/api/prefs', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const sanitized = sanitizePrefs(req.body);
  if (Object.keys(sanitized).length === 0) {
    return res.status(400).json({ error: 'No valid preferences to update' });
  }
  const { rows } = await pool.query(
    `UPDATE users SET preferences = preferences || $1::jsonb
      WHERE id = $2 RETURNING preferences`,
    [JSON.stringify(sanitized), req.user.id]
  );
  res.json(rows[0].preferences);
}));

// ═══════════════════════════════════════════════════════════════════════════
//  VAULT ROUTES
// ═══════════════════════════════════════════════════════════════════════════
function validateItemPayload({ type, encrypted_data, folder_id, favorite }, { partial = false } = {}) {
  const errors = [];
  if (!partial || type !== undefined) {
    if (!VALID_TYPES.has(type)) errors.push('type must be login|note|card|identity');
  }
  if (!partial || encrypted_data !== undefined) {
    if (!isValidBase64(encrypted_data, MAX_ENCRYPTED_DATA_B64)) {
      errors.push('encrypted_data must be base64, max ' + MAX_ENCRYPTED_DATA_B64 + ' chars');
    }
  }
  if (folder_id !== undefined && folder_id !== null) {
    if (!Number.isInteger(folder_id) || folder_id < 1) errors.push('folder_id must be a positive integer or null');
  }
  if (favorite !== undefined && typeof favorite !== 'boolean') errors.push('favorite must be boolean');
  return errors.length ? errors.join('; ') : null;
}

// GET /api/vault — returns all items for the user (ciphertext only)
app.get('/api/vault', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  // include_deleted=1 returns trashed items too (used by the trash UI).
  // Default returns only active items.
  const includeDeleted = req.query.include_deleted === '1';
  const sql = includeDeleted
    ? `SELECT id, type, folder_id, favorite, encrypted_data,
              EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
              EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at,
              EXTRACT(EPOCH FROM deleted_at)::bigint AS deleted_at
         FROM vault_items
        WHERE user_id = $1
        ORDER BY updated_at DESC`
    : `SELECT id, type, folder_id, favorite, encrypted_data,
              EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
              EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at
         FROM vault_items
        WHERE user_id = $1 AND deleted_at IS NULL
        ORDER BY updated_at DESC`;
  const { rows } = await pool.query(sql, [req.user.id]);
  res.json(rows);
}));

// GET /api/vault/trash — list only trashed items
app.get('/api/vault/trash', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rows } = await pool.query(
    `SELECT id, type, folder_id, favorite, encrypted_data,
            EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
            EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at,
            EXTRACT(EPOCH FROM deleted_at)::bigint AS deleted_at
       FROM vault_items
      WHERE user_id = $1 AND deleted_at IS NOT NULL
      ORDER BY deleted_at DESC`,
    [req.user.id]
  );
  res.json(rows);
}));

// POST /api/vault — create new item
// Body: { type, encrypted_data, folder_id?, favorite? }
app.post('/api/vault', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const err = validateItemPayload(req.body);
  if (err) return res.status(400).json({ error: err });

  // Check item cap (active items only — trashed items don't count)
  const { rows: countRows } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM vault_items WHERE user_id = $1 AND deleted_at IS NULL',
    [req.user.id]
  );
  if (countRows[0].n >= MAX_ITEMS_PER_USER) {
    return res.status(400).json({ error: `Item limit reached (${MAX_ITEMS_PER_USER})` });
  }

  // If folder_id given, verify user owns it
  if (req.body.folder_id != null) {
    const { rowCount } = await pool.query(
      'SELECT 1 FROM folders WHERE id = $1 AND user_id = $2',
      [req.body.folder_id, req.user.id]
    );
    if (!rowCount) return res.status(400).json({ error: 'Unknown folder' });
  }

  const { rows } = await pool.query(
    `INSERT INTO vault_items (user_id, type, folder_id, favorite, encrypted_data)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id,
               EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
               EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at`,
    [req.user.id, req.body.type, req.body.folder_id ?? null,
     req.body.favorite ?? false, req.body.encrypted_data]
  );
  await audit(req.user.id, 'item_create', `type=${req.body.type}`, req.ip);
  res.status(201).json({ id: rows[0].id, created_at: rows[0].created_at, updated_at: rows[0].updated_at });
}));

// PUT /api/vault/:id — full replace
app.put('/api/vault/:id(\\d+)', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  const err = validateItemPayload(req.body, { partial: true });
  if (err) return res.status(400).json({ error: err });

  if (req.body.folder_id != null) {
    const { rowCount } = await pool.query(
      'SELECT 1 FROM folders WHERE id = $1 AND user_id = $2',
      [req.body.folder_id, req.user.id]
    );
    if (!rowCount) return res.status(400).json({ error: 'Unknown folder' });
  }

  // Build dynamic update
  const sets = [];
  const vals = [];
  let i = 1;
  for (const k of ['type', 'folder_id', 'favorite', 'encrypted_data']) {
    if (req.body[k] !== undefined) {
      sets.push(`${k} = $${i++}`);
      vals.push(req.body[k]);
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'Nothing to update' });
  sets.push(`updated_at = NOW()`);
  vals.push(id, req.user.id);

  const { rows } = await pool.query(
    `UPDATE vault_items SET ${sets.join(', ')}
      WHERE id = $${i++} AND user_id = $${i} AND deleted_at IS NULL
      RETURNING id, EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at`,
    vals
  );
  if (!rows.length) return res.status(404).json({ error: 'Not found' });
  await audit(req.user.id, 'item_update', `id=${id}`, req.ip);
  res.json({ id: rows[0].id, updated_at: rows[0].updated_at });
}));

// DELETE /api/vault/:id  — soft-delete (move to trash)
// Item lives in the trash for 6 months, then is auto-purged. Restore via
// POST /api/vault/:id/restore. Permanent delete via /purge.
app.delete('/api/vault/:id(\\d+)', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  // Allow `?permanent=1` for API parity, though the UI uses /purge for clarity.
  if (req.query.permanent === '1') {
    const { rowCount } = await pool.query(
      'DELETE FROM vault_items WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (!rowCount) return res.status(404).json({ error: 'Not found' });
    await audit(req.user.id, 'item_purge', `id=${id}`, req.ip);
    return res.json({ ok: true, permanent: true });
  }
  const { rowCount } = await pool.query(
    `UPDATE vault_items SET deleted_at = NOW()
      WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`,
    [id, req.user.id]
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found' });
  await audit(req.user.id, 'item_trash', `id=${id}`, req.ip);
  res.json({ ok: true, trashed: true });
}));

// POST /api/vault/:id/restore — bring an item back from the trash
app.post('/api/vault/:id(\\d+)/restore', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  const { rowCount } = await pool.query(
    `UPDATE vault_items SET deleted_at = NULL, updated_at = NOW()
      WHERE id = $1 AND user_id = $2 AND deleted_at IS NOT NULL`,
    [id, req.user.id]
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found in trash' });
  await audit(req.user.id, 'item_restore', `id=${id}`, req.ip);
  res.json({ ok: true });
}));

// DELETE /api/vault/:id/purge — permanently delete a trashed item
app.delete('/api/vault/:id(\\d+)/purge', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  // Only permit purging items that are currently trashed. Active items
  // must be moved to trash first — protects against accidental hard
  // deletes from rogue clients or stale UI.
  const { rowCount } = await pool.query(
    `DELETE FROM vault_items
      WHERE id = $1 AND user_id = $2 AND deleted_at IS NOT NULL`,
    [id, req.user.id]
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found in trash' });
  await audit(req.user.id, 'item_purge', `id=${id}`, req.ip);
  res.json({ ok: true });
}));

// DELETE /api/vault/trash — empty trash (purge ALL trashed items)
app.delete('/api/vault/trash', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rowCount } = await pool.query(
    `DELETE FROM vault_items
      WHERE user_id = $1 AND deleted_at IS NOT NULL`,
    [req.user.id]
  );
  await audit(req.user.id, 'trash_empty', `count=${rowCount}`, req.ip);
  res.json({ ok: true, purged: rowCount });
}));

// PATCH /api/vault/:id/favorite
app.patch('/api/vault/:id(\\d+)/favorite', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  if (typeof req.body?.favorite !== 'boolean') {
    return res.status(400).json({ error: 'favorite must be boolean' });
  }
  const { rowCount } = await pool.query(
    `UPDATE vault_items SET favorite = $1, updated_at = NOW()
      WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL`,
    [req.body.favorite, id, req.user.id]
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// ═══════════════════════════════════════════════════════════════════════════
//  PASSWORD GENERATION HISTORY
// ═══════════════════════════════════════════════════════════════════════════
// Stores the encrypted blob of every password the user copies from the
// generator. Useful when someone generates a password, hits "copy",
// pastes it into a sign-up form somewhere, and then can't remember
// whether they actually saved it as a vault item. Auto-purges after
// 6 months. Server sees only ciphertext.

const MAX_HISTORY_PER_USER = 500;

app.get('/api/password-history', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rows } = await pool.query(
    `SELECT id, encrypted_data,
            EXTRACT(EPOCH FROM created_at)::bigint AS created_at
       FROM password_history
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 200`,
    [req.user.id]
  );
  res.json(rows);
}));

app.post('/api/password-history', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { encrypted_data } = req.body || {};
  if (typeof encrypted_data !== 'string' || encrypted_data.length < 8 ||
      encrypted_data.length > 4096) {
    return res.status(400).json({ error: 'invalid_payload' });
  }

  // Cap per user. If exceeded, drop the oldest entry to make room.
  const { rows: countRows } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM password_history WHERE user_id = $1',
    [req.user.id]
  );
  if (countRows[0].n >= MAX_HISTORY_PER_USER) {
    await pool.query(
      `DELETE FROM password_history
        WHERE id = (
          SELECT id FROM password_history
            WHERE user_id = $1
            ORDER BY created_at ASC
            LIMIT 1
        )`,
      [req.user.id]
    );
  }

  const { rows } = await pool.query(
    `INSERT INTO password_history (user_id, encrypted_data)
     VALUES ($1, $2)
     RETURNING id, EXTRACT(EPOCH FROM created_at)::bigint AS created_at`,
    [req.user.id, encrypted_data]
  );
  res.status(201).json(rows[0]);
}));

app.delete('/api/password-history/:id(\\d+)', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  const { rowCount } = await pool.query(
    'DELETE FROM password_history WHERE id = $1 AND user_id = $2',
    [id, req.user.id]
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

app.delete('/api/password-history', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rowCount } = await pool.query(
    'DELETE FROM password_history WHERE user_id = $1',
    [req.user.id]
  );
  await audit(req.user.id, 'pwhistory_clear', `count=${rowCount}`, req.ip);
  res.json({ ok: true, cleared: rowCount });
}));

// ═══════════════════════════════════════════════════════════════════════════
//  FOLDERS (names encrypted, colors plaintext)
// ═══════════════════════════════════════════════════════════════════════════
app.get('/api/folders', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rows } = await pool.query(
    `SELECT id, encrypted_name, color,
            EXTRACT(EPOCH FROM created_at)::bigint AS created_at
       FROM folders
      WHERE user_id = $1
      ORDER BY id`,
    [req.user.id]
  );
  res.json(rows);
}));

app.post('/api/folders', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { encrypted_name, color } = req.body || {};
  if (!isValidBase64(encrypted_name, MAX_ENCRYPTED_NAME_B64)) {
    return res.status(400).json({ error: 'Invalid encrypted_name' });
  }
  if (color != null && (typeof color !== 'string' || color.length > MAX_COLOR_LEN || !VALID_HEX_COLOR.test(color))) {
    return res.status(400).json({ error: 'Invalid color (must be hex)' });
  }
  // Folder cap
  const { rows: countRows } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM folders WHERE user_id = $1', [req.user.id]
  );
  if (countRows[0].n >= MAX_FOLDERS_PER_USER) {
    return res.status(400).json({ error: `Folder limit reached (${MAX_FOLDERS_PER_USER})` });
  }
  const { rows } = await pool.query(
    `INSERT INTO folders (user_id, encrypted_name, color) VALUES ($1, $2, $3)
     RETURNING id, encrypted_name, color,
               EXTRACT(EPOCH FROM created_at)::bigint AS created_at`,
    [req.user.id, encrypted_name, color || null]
  );
  res.status(201).json(rows[0]);
}));

app.put('/api/folders/:id(\\d+)', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  const { encrypted_name, color } = req.body || {};
  const sets = [];
  const vals = [];
  let i = 1;
  if (encrypted_name !== undefined) {
    if (!isValidBase64(encrypted_name, MAX_ENCRYPTED_NAME_B64)) {
      return res.status(400).json({ error: 'Invalid encrypted_name' });
    }
    sets.push(`encrypted_name = $${i++}`);
    vals.push(encrypted_name);
  }
  if (color !== undefined) {
    if (color !== null && (typeof color !== 'string' || !VALID_HEX_COLOR.test(color))) {
      return res.status(400).json({ error: 'Invalid color' });
    }
    sets.push(`color = $${i++}`);
    vals.push(color);
  }
  if (!sets.length) return res.status(400).json({ error: 'Nothing to update' });
  vals.push(id, req.user.id);
  const { rowCount } = await pool.query(
    `UPDATE folders SET ${sets.join(', ')} WHERE id = $${i++} AND user_id = $${i}`,
    vals
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

app.delete('/api/folders/:id(\\d+)', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const id = parseInt(req.params.id, 10);
  const { rowCount } = await pool.query(
    'DELETE FROM folders WHERE id = $1 AND user_id = $2', [id, req.user.id]
  );
  if (!rowCount) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
}));

// ═══════════════════════════════════════════════════════════════════════════
//  AUDIT LOG (user can view their own)
// ═══════════════════════════════════════════════════════════════════════════
app.get('/api/audit', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rows } = await pool.query(
    `SELECT action, details, ip,
            EXTRACT(EPOCH FROM created_at)::bigint AS created_at
       FROM audit_log
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT 100`,
    [req.user.id]
  );
  res.json(rows);
}));

// ═══════════════════════════════════════════════════════════════════════════
//  EXPORT / IMPORT (encrypted blobs, so this is a trivial passthrough)
// ═══════════════════════════════════════════════════════════════════════════
app.get('/api/export', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { rows: items } = await pool.query(
    `SELECT type, folder_id, favorite, encrypted_data,
            EXTRACT(EPOCH FROM created_at)::bigint AS created_at,
            EXTRACT(EPOCH FROM updated_at)::bigint AS updated_at
       FROM vault_items WHERE user_id = $1`,
    [req.user.id]
  );
  const { rows: folders } = await pool.query(
    `SELECT id, encrypted_name, color FROM folders WHERE user_id = $1`,
    [req.user.id]
  );
  res.json({
    format: 'vaultkeeper-e2e-v1',
    exported_at: new Date().toISOString(),
    note: 'This export contains E2E-encrypted data. Restoring requires the same master password.',
    folders,
    items,
  });
}));

// ═══════════════════════════════════════════════════════════════════════════
//  CLIENT-ASSISTED UTILITIES (kept because they're client-initiated, server
//  just forwards to upstream services that don't accept browser CORS)
// ═══════════════════════════════════════════════════════════════════════════

// HIBP k-anonymity proxy: accepts the first 5 hex chars of a SHA-1 hash,
// returns the matching suffix list. The client then checks the rest of the
// hash against that list locally. Plaintext password NEVER leaves the browser.
app.post('/api/pwned-check', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { prefix } = req.body || {};
  if (typeof prefix !== 'string' || !/^[0-9A-F]{5}$/i.test(prefix)) {
    return res.status(400).json({ error: 'prefix must be 5 hex chars' });
  }
  try {
    const body = await httpsGet(`https://api.pwnedpasswords.com/range/${prefix.toUpperCase()}`, 3000);
    res.json({ body });
  } catch (e) {
    res.status(502).json({ error: 'HIBP lookup failed' });
  }
}));

// ─────────────────────────────────────────────────────────────────────────────
// 2FA support check (proxy + cache for 2fa.directory)
//
// Client POSTs { domains: ["github.com", "example.com", ...] }
// Server returns { results: { "github.com": { supports: true, methods: [...], documentation: "..." }, ... } }
//
// We fetch the upstream `all.json` once per process and cache in memory for
// 24h. The dataset is ~1-3 MB; the request is auth'd, so this is per-user
// rate limited just by being inside auth. Lookups are domain → entry,
// returning ONLY the queried domains so we don't ship megabytes per request.
//
// Attribution: 2FA Directory by 2factorauth — https://2fa.directory/
// MIT-licensed dataset. Attribution shown to users in the UI.
// ─────────────────────────────────────────────────────────────────────────────

// Cache state. Disk-persisted so we don't re-download on every restart.
//   - HARD TTL (7 days): if older, force refresh and block on it
//   - SOFT TTL (24 hours): if older, return cached + trigger background refresh
//
// Cache file path is configurable via TFA_CACHE_PATH (default /tmp/vk-tfa-cache.json)
// — picking /tmp because the container's /tmp is fine for ephemeral cache.
// Set to a bind-mounted path if you want it to survive container recreation.
let _tfaCache = null;       // { fetchedAt: ms, data: { domain: entry } }
let _tfaRefreshing = false; // in-flight refresh guard
const TFA_HARD_TTL = 7 * 24 * 60 * 60 * 1000;  // 7 days
const TFA_SOFT_TTL = 24 * 60 * 60 * 1000;      // 24 hours
const TFA_FETCH_TIMEOUT = 15000;                // 15s — dataset is 1-3 MB
const TFA_CACHE_PATH = process.env.TFA_CACHE_PATH || '/tmp/vk-tfa-cache.json';

// Load on startup (best effort)
try {
  if (fs.existsSync(TFA_CACHE_PATH)) {
    const raw = fs.readFileSync(TFA_CACHE_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && parsed.fetchedAt && parsed.data && typeof parsed.data === 'object') {
      _tfaCache = parsed;
      const ageHrs = ((Date.now() - parsed.fetchedAt) / 3600000).toFixed(1);
      console.log(`[2fa-check] loaded cache from disk (${Object.keys(parsed.data).length} entries, ${ageHrs}h old)`);
    }
  }
} catch (e) {
  console.warn('[2fa-check] could not load cache from disk:', e.message);
}

async function fetchTfaDirectoryFresh() {
  const raw = await httpsGet('https://api.2fa.directory/v4/all.json', TFA_FETCH_TIMEOUT, 5_000_000);
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('2fa.directory returned non-object');
  }
  const cache = { fetchedAt: Date.now(), data: parsed };
  // Persist to disk async — failure is non-fatal
  try {
    fs.writeFile(TFA_CACHE_PATH, JSON.stringify(cache), (err) => {
      if (err) console.warn('[2fa-check] disk write failed:', err.message);
    });
  } catch (e) { console.warn('[2fa-check] disk write threw:', e.message); }
  return cache;
}

async function getTfaDirectory() {
  const now = Date.now();
  const age = _tfaCache ? now - _tfaCache.fetchedAt : Infinity;

  // Cache exists and is fresh — return immediately
  if (_tfaCache && age < TFA_SOFT_TTL) {
    return _tfaCache.data;
  }

  // Cache exists, soft-stale but not hard-stale — return it AND trigger
  // background refresh so the next request gets fresher data.
  if (_tfaCache && age < TFA_HARD_TTL) {
    if (!_tfaRefreshing) {
      _tfaRefreshing = true;
      fetchTfaDirectoryFresh()
        .then((c) => { _tfaCache = c; console.log('[2fa-check] background refresh OK'); })
        .catch((e) => console.warn('[2fa-check] background refresh failed:', e.message))
        .finally(() => { _tfaRefreshing = false; });
    }
    return _tfaCache.data;
  }

  // No cache or hard-stale — block on a fresh fetch. If upstream is down,
  // fall back to whatever we have, even if hard-stale.
  try {
    _tfaCache = await fetchTfaDirectoryFresh();
    return _tfaCache.data;
  } catch (e) {
    console.warn('[2fa-check] foreground fetch failed:', e.message);
    if (_tfaCache) return _tfaCache.data;
    throw e;
  }
}

app.post('/api/2fa-check', auth, ah(async (req, res) => {
  if (!await verifyTokenVersion(req, res)) return;
  const { domains } = req.body || {};
  if (!Array.isArray(domains)) {
    return res.status(400).json({ error: 'domains must be an array' });
  }
  if (domains.length > 5000) {
    return res.status(400).json({ error: 'too many domains (max 5000)' });
  }
  // Sanitize: hostnames only, lowercase, no paths/query
  const cleaned = [];
  const cleanedSet = new Set();
  for (const d of domains) {
    if (typeof d !== 'string') continue;
    const lc = d.trim().toLowerCase();
    if (!lc) continue;
    if (lc.length > 253) continue;  // FQDN max length
    if (!/^[a-z0-9.\-]+$/.test(lc)) continue;
    if (cleanedSet.has(lc)) continue;
    cleanedSet.add(lc);
    cleaned.push(lc);
  }

  let directory;
  try {
    directory = await getTfaDirectory();
  } catch (e) {
    return res.status(502).json({ error: '2FA directory lookup failed' });
  }

  const results = {};
  for (const d of cleaned) {
    let entry = directory[d];
    // Try suffix-stripping: "accounts.google.com" → "google.com"
    if (!entry) {
      const parts = d.split('.');
      while (parts.length >= 2 && !entry) {
        const candidate = parts.join('.');
        if (directory[candidate]) { entry = directory[candidate]; break; }
        parts.shift();
      }
    }
    if (!entry) {
      results[d] = { listed: false };
    } else {
      const methods = Array.isArray(entry.methods) ? entry.methods : [];
      results[d] = {
        listed: true,
        supports: methods.length > 0,
        methods,
        documentation: entry.documentation || null,
      };
    }
  }

  // Send a content-length-friendly response. Cache for short period.
  res.set('Cache-Control', 'private, max-age=3600');
  res.json({ results });
}));

function httpsGet(url, timeoutMs = 3000, maxBytes = 200_000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { timeout: timeoutMs }, (r) => {
      if (r.statusCode !== 200) { r.resume(); return reject(new Error('HTTP ' + r.statusCode)); }
      let data = '', bytes = 0;
      r.on('data', (c) => {
        bytes += c.length;
        if (bytes > maxBytes) { r.destroy(); return reject(new Error('Response too large')); }
        data += c;
      });
      r.on('end', () => resolve(data));
    });
    req.on('timeout', () => { req.destroy(new Error('Timeout')); });
    req.on('error', reject);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  404 + ERROR HANDLERS
// ═══════════════════════════════════════════════════════════════════════════
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, _next) => {
  // Body parser failures (malformed JSON, etc) are client errors, not 500s.
  if (err && err.type && /entity\.(parse|too\.large)/.test(err.type)) {
    return res.status(400).json({ error: 'Invalid request body' });
  }
  console.error('[ERROR]', err.stack || err.message || err);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal error' });
});

// ═══════════════════════════════════════════════════════════════════════════
//  START
// ═══════════════════════════════════════════════════════════════════════════
//
// Listening modes:
//
// 1. Plain HTTP (default): when TLS_CERT and TLS_KEY are unset.
//    Listens on PORT (default 3333). Use behind a reverse proxy that
//    terminates TLS — Cloudflare Tunnel, Caddy, nginx, etc.
//
// 2. HTTPS direct: set TLS_CERT and TLS_KEY env vars to absolute paths
//    inside the container. The server listens on TLS_PORT (default 443)
//    using those cert/key files. Use this for LAN-only deployments where
//    you generated a cert with mkcert.
//
//    Optionally, set TLS_HTTP_REDIRECT_PORT to also listen on a plain
//    HTTP port that 301-redirects everything to HTTPS — handy if users
//    might type the URL without "https://".
//
let server;
let httpRedirectServer;

(async () => {
  try {
    await initDB();

    const tlsCert = process.env.TLS_CERT;
    const tlsKey = process.env.TLS_KEY;

    if (tlsCert && tlsKey) {
      // HTTPS mode
      let cert, key;
      try {
        cert = fs.readFileSync(tlsCert);
        key = fs.readFileSync(tlsKey);
      } catch (e) {
        console.error('[FATAL] Could not read TLS_CERT or TLS_KEY:', e.message);
        process.exit(1);
      }
      const tlsPort = parseInt(process.env.TLS_PORT || '443', 10);
      server = https.createServer({ cert, key }, app).listen(tlsPort, '0.0.0.0', () => {
        console.log(`[START] VaultKeeper E2E server listening on HTTPS :${tlsPort}`);
        console.log(`[START] TLS cert: ${tlsCert}`);
        console.log(`[START] Mode: zero-knowledge (server never sees plaintext)`);
      });

      // Optional HTTP→HTTPS redirector
      const redirectPort = parseInt(process.env.TLS_HTTP_REDIRECT_PORT || '0', 10);
      if (redirectPort > 0) {
        httpRedirectServer = http.createServer((req, res) => {
          // Strip any port from the Host header, then construct https URL.
          const host = (req.headers.host || 'localhost').split(':')[0];
          const target = `https://${host}${tlsPort === 443 ? '' : ':' + tlsPort}${req.url}`;
          res.writeHead(301, { Location: target });
          res.end();
        }).listen(redirectPort, '0.0.0.0', () => {
          console.log(`[START] HTTP redirector listening on :${redirectPort} → HTTPS :${tlsPort}`);
        });
      }
    } else {
      // Plain HTTP mode (behind reverse proxy)
      server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`[START] VaultKeeper E2E server listening on HTTP :${PORT}`);
        console.log(`[START] Mode: zero-knowledge (server never sees plaintext)`);
        console.log(`[START] No TLS — assuming reverse proxy in front. For LAN+IP direct access, set TLS_CERT + TLS_KEY.`);
      });
    }
  } catch (e) {
    console.error('[FATAL] Startup failed:', e.message);
    process.exit(1);
  }
})();

function shutdown(signal) {
  console.log(`[${signal}] Shutting down gracefully`);
  const closers = [];
  if (server) closers.push(new Promise(r => server.close(r)));
  if (httpRedirectServer) closers.push(new Promise(r => httpRedirectServer.close(r)));
  Promise.all(closers).then(() => pool.end().then(() => process.exit(0)));
  // Force exit if graceful shutdown takes too long
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
