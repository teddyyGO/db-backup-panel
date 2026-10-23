'use strict';

/**
 * db-backuper — a tiny, secure MySQL / MariaDB auto-backup panel.
 *
 * What it does:
 *   - Runs mysqldump / mariadb-dump on a schedule (default every 30 min),
 *     gzip-compresses the output, and stores it in a persistent folder.
 *   - Serves a single-page panel to configure the connection, trigger backups,
 *     browse/download (as ZIP) and delete backups to free space.
 *
 * Security model (see README):
 *   - Panel is gated by APP_PASSWORD (constant-time compare, rate limited).
 *   - The DB connection string is encrypted at rest with AES-256-GCM using a
 *     key derived from APP_SECRET. It is write-only in the UI and is never
 *     returned to the browser and never logged.
 *   - Credentials are handed to the dump tool via a 0600 --defaults-extra-file
 *     that is deleted immediately after, so the password never appears on argv
 *     / in the process list.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const zlib = require('zlib');
const crypto = require('crypto');
const { pipeline, Transform } = require('stream');
const { spawn, spawnSync } = require('child_process');
const express = require('express');
const archiver = require('archiver');

// ---------------------------------------------------------------------------
// Minimal .env loader (no dependency). Only sets vars that aren't already set.
// ---------------------------------------------------------------------------
(function loadDotEnv() {
  try {
    const raw = fs.readFileSync(path.join(__dirname, '.env'), 'utf8');
    for (const line of raw.split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/i);
      if (!m) continue;
      let val = m[2];
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (process.env[m[1]] === undefined) process.env[m[1]] = val;
    }
  } catch { /* no .env file — fine in production */ }
})();

// ---------------------------------------------------------------------------
// Config / constants
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
// Bind address. Default 0.0.0.0 (Railway/containers). Set to 127.0.0.1 on a VPS
// so the panel is reachable ONLY through an SSH tunnel — never from the internet.
const BIND_HOST = process.env.BIND_HOST || '0.0.0.0';
// `Secure` cookies require HTTPS. When the panel is reached over an SSH tunnel
// (http://localhost:PORT) the traffic is already encrypted by SSH, so this can
// be turned off. ONLY set COOKIE_SECURE=false when access is via tunnel/localhost.
const COOKIE_SECURE = process.env.COOKIE_SECURE !== undefined
  ? process.env.COOKIE_SECURE === 'true'
  : IS_PROD;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const ACTIVITY_FILE = path.join(DATA_DIR, 'activity.log');

const APP_PASSWORD = process.env.APP_PASSWORD || '';
const APP_SECRET = process.env.APP_SECRET || '';

// Optional: force a specific dump binary, or append extra dump flags
// (e.g. DUMP_EXTRA_ARGS="--ssl" or "--set-gtid-purged=OFF").
const DUMP_BIN_ENV = process.env.DUMP_BIN || '';
const DUMP_EXTRA_ARGS = (process.env.DUMP_EXTRA_ARGS || '').trim();
// Hard cap on a single dump so a hung remote connection can't get the backup
// engine stuck "running" forever (which would silently skip all future runs).
const MAX_DUMP_MIN = Math.max(1, parseInt(process.env.DUMP_TIMEOUT_MIN, 10) || 60);

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h
const DEFAULT_INTERVAL_MIN = 30;
const DEFAULT_FULL_INTERVAL_MIN = 1440; // full backup (incl. log rows) once a day
const MIN_INTERVAL_MIN = 1;
const MAX_INTERVAL_MIN = 90 * 24 * 60; // up to 90 days (weekly=10080, monthly≈43200)
const BACKUP_EXT = '.sql.gz';

// Fail fast if the app is not configured securely.
(function requireSecrets() {
  const missing = [];
  if (!APP_PASSWORD) missing.push('APP_PASSWORD');
  if (!APP_SECRET || APP_SECRET.length < 16) missing.push('APP_SECRET (>= 16 chars)');
  // Refuse the placeholder values shipped in .env.example.
  if (/^change-me/i.test(APP_PASSWORD)) missing.push('APP_PASSWORD (still the .env.example placeholder)');
  if (/^change-me/i.test(APP_SECRET)) missing.push('APP_SECRET (still the .env.example placeholder)');
  if (missing.length) {
    console.error(
      '\n[db-backuper] Refusing to start. Missing required env vars: ' +
      missing.join(', ') +
      '\nGenerate a secret with:  node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"\n'
    );
    process.exit(1);
  }
})();

fs.mkdirSync(BACKUP_DIR, { recursive: true });

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------
const ENC_KEY = crypto.scryptSync(APP_SECRET, 'db-backuper.enc.v1', 32);
const SIGN_KEY = crypto.scryptSync(APP_SECRET, 'db-backuper.sign.v1', 32);

function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

function decryptSecret(blobB64) {
  const blob = Buffer.from(blobB64, 'base64');
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function signSession(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', SIGN_KEY).update(body).digest());
  return `${body}.${sig}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = b64url(crypto.createHmac('sha256', SIGN_KEY).update(body).digest());
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(fromB64url(body).toString('utf8'));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

// Compare fixed-length HMACs so neither content nor length leaks via timing.
function safeEqual(a, b) {
  const ah = crypto.createHmac('sha256', SIGN_KEY).update(String(a)).digest();
  const bh = crypto.createHmac('sha256', SIGN_KEY).update(String(b)).digest();
  return crypto.timingSafeEqual(ah, bh);
}

// ---------------------------------------------------------------------------
// Persistent config (interval + encrypted connection string)
// ---------------------------------------------------------------------------
let config = {
  connectionEnc: null,
  intervalMinutes: DEFAULT_INTERVAL_MIN,
  logTables: [],                                 // rows skipped by frequent backups
  fullIntervalMinutes: DEFAULT_FULL_INTERVAL_MIN, // how often to include log rows
  updatedAt: null,
};

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    config.connectionEnc = raw.connectionEnc || null;
    config.intervalMinutes = clampInterval(raw.intervalMinutes || DEFAULT_INTERVAL_MIN);
    config.logTables = Array.isArray(raw.logTables) ? raw.logTables : [];
    config.fullIntervalMinutes = clampInterval(raw.fullIntervalMinutes || DEFAULT_FULL_INTERVAL_MIN);
    config.updatedAt = raw.updatedAt || null;
  } catch { /* first run — defaults */ }
}

// Table names are passed to mysqldump as arguments — keep them to safe identifier
// characters so nothing can smuggle in an extra flag or shell-ish token.
function parseTableList(input) {
  const raw = Array.isArray(input) ? input : String(input || '').split(/[\s,;]+/);
  const seen = new Set();
  for (const t of raw) {
    const name = String(t).trim();
    if (name && /^[A-Za-z0-9_$]+$/.test(name)) seen.add(name);
  }
  return [...seen].slice(0, 200);
}

function saveConfig() {
  const tmp = CONFIG_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(config, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, CONFIG_FILE);
}

function clampInterval(n) {
  n = parseInt(n, 10);
  if (!Number.isFinite(n)) return DEFAULT_INTERVAL_MIN;
  return Math.min(MAX_INTERVAL_MIN, Math.max(MIN_INTERVAL_MIN, n));
}

function getConnectionString() {
  if (!config.connectionEnc) return null;
  try { return decryptSecret(config.connectionEnc); }
  catch (e) { console.error('[db-backuper] Failed to decrypt connection string (wrong APP_SECRET?)'); return null; }
}

// ---------------------------------------------------------------------------
// Persistent activity log ("the console that never forgets").
// Append-only JSON-lines on the volume — survives restarts/redeploys and is
// never auto-truncated. Never throws, so logging can't break the app.
// ---------------------------------------------------------------------------
const MAX_ACTIVITY_READ = 1_000_000; // bytes read from the tail for the panel

function humanBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}

function logEvent(level, event, message, extra) {
  const entry = { ts: Date.now(), level, event, message };
  if (extra && typeof extra === 'object') Object.assign(entry, extra);
  try {
    fs.appendFileSync(ACTIVITY_FILE, JSON.stringify(entry) + '\n', { mode: 0o600 });
  } catch (e) {
    console.error('[db-backuper] could not write activity log:', e.message);
  }
  const out = `[${event}] ${message}`;
  if (level === 'error') console.error('[db-backuper]', out);
  else console.log('[db-backuper]', out);
  return entry;
}

function readActivity(limit) {
  limit = Math.min(2000, Math.max(1, parseInt(limit, 10) || 500));
  let buf;
  try {
    const stat = fs.statSync(ACTIVITY_FILE);
    const start = Math.max(0, stat.size - MAX_ACTIVITY_READ);
    const len = stat.size - start;
    const fd = fs.openSync(ACTIVITY_FILE, 'r');
    buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, start);
    fs.closeSync(fd);
  } catch { return { entries: [], total: 0 }; }
  const lines = buf.toString('utf8').split('\n').filter(Boolean);
  const entries = [];
  for (const l of lines) { try { entries.push(JSON.parse(l)); } catch {} }
  return { entries: entries.slice(-limit).reverse(), total: entries.length };
}

// ---------------------------------------------------------------------------
// Backup engine
// ---------------------------------------------------------------------------
const state = { running: false, lastRun: null, lastResult: null, nextRunAt: null, nextFullRunAt: null };
const timers = { data: null, full: null };
let cachedDumpBin; // undefined = not resolved yet, null = none found

function parseMysqlConn(conn) {
  const u = new URL(conn);
  if (!/^(mysql|mariadb):$/.test(u.protocol)) {
    throw new Error('Connection string must start with mysql:// or mariadb://');
  }
  const database = decodeURIComponent(u.pathname.replace(/^\//, ''));
  if (!database) {
    throw new Error('Connection string must include a database name, e.g. mysql://user:pass@host:3306/dbname');
  }
  // The database name is passed as a positional argument; a leading '-' would be
  // parsed as an option (e.g. --result-file=...), so reject it and control chars.
  if (database.startsWith('-') || /[\x00-\x1f]/.test(database)) {
    throw new Error('Invalid database name in connection string');
  }
  const sslmode = (u.searchParams.get('sslmode') || '').toLowerCase();
  return {
    host: decodeURIComponent(u.hostname),
    port: u.port || '3306',
    user: u.username ? decodeURIComponent(u.username) : 'root',
    password: u.password ? decodeURIComponent(u.password) : '',
    database,
    ssl: u.searchParams.get('ssl') === 'true' || sslmode === 'require' || sslmode === 'required',
  };
}

// Resolve the dump binary once. Prefer mariadb-dump, fall back to mysqldump.
function resolveDumpBin() {
  if (cachedDumpBin !== undefined) return cachedDumpBin;
  const candidates = DUMP_BIN_ENV ? [DUMP_BIN_ENV] : ['mariadb-dump', 'mysqldump'];
  for (const c of candidates) {
    try {
      const r = spawnSync(c, ['--version'], { stdio: 'ignore' });
      if (!r.error && r.status === 0) { cachedDumpBin = c; return c; }
    } catch { /* try next */ }
  }
  cachedDumpBin = null;
  return null;
}

// MySQL option-file value quoting (handles spaces, '#', backslash, quotes).
function cnfQuote(v) {
  // Escape newlines too, otherwise a crafted value could inject extra option lines.
  return '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')
    .replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
}

function writeDefaultsFile(c) {
  const lines = [
    '[client]',
    `host=${cnfQuote(c.host)}`,
    `port=${c.port}`,
    `user=${cnfQuote(c.user)}`,
    `password=${cnfQuote(c.password)}`,
  ];
  if (c.ssl) lines.push('ssl=1');
  const p = path.join(os.tmpdir(), `dbbk-${crypto.randomBytes(9).toString('hex')}.cnf`);
  fs.writeFileSync(p, lines.join('\n') + '\n', { mode: 0o600 });
  return p;
}

function timestampName(kind = 'full') {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `backup_${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_` +
    `${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}_${kind}${BACKUP_EXT}`;
}

const PROGRESS_LOG_MS = 15000; // how often to log a "still dumping" line
const STALL_WARN_MS = 30000;   // no new data for this long => warn in the console

// A Transform for the dump's stdout that logs the connection + throttled
// progress to the activity console, and exposes byte count / connected state.
// Passes every chunk through unchanged, so it never corrupts the dump.
// A watchdog reports stalls (no new data), so a frozen remote link is visible
// instead of the console just going silent.
// mysqldump/mariadb-dump emit these section-comment headers exactly once per
// object, and they cleanly separate base tables from views (unlike raw
// "CREATE TABLE", which some tools also use for view placeholders).
const TABLE_NEEDLE = 'Table structure for table `';    // one per base table
const VIEW_NEEDLE = 'Final view structure for view `'; // one per view
const DONE_MARKER = '-- Dump completed';  // printed only after a clean finish

// Count non-overlapping occurrences of needle in (carry+str); returns the new
// count and the carry to prepend next time so a boundary-split match isn't lost.
function scan(carry, str, needle) {
  const hay = carry + str;
  let i = 0, n = 0;
  while ((i = hay.indexOf(needle, i)) !== -1) { n++; i += needle.length; }
  return { n, carry: hay.slice(-(needle.length - 1)) };
}

function makeDumpProgress(c, trigger) {
  let rawBytes = 0, connected = false, lastProgressAt = 0, lastLoggedBytes = 0, lastDataAt = 0, watchdog = null;
  // Scan the SQL as it streams to count objects and detect the completion
  // marker, so every backup can self-report what it captured.
  let tableCount = 0, viewCount = 0;
  let tCarry = '', vCarry = '', endTail = '';

  function startWatchdog() {
    watchdog = setInterval(() => {
      const idle = Date.now() - lastDataAt;
      if (idle >= STALL_WARN_MS) {
        logEvent('info', 'backup', `Still connected, but no new data for ${Math.round(idle / 1000)}s — the remote server may be slow or throttling…`, { trigger });
      }
    }, STALL_WARN_MS);
    if (watchdog.unref) watchdog.unref();
  }

  const stream = new Transform({
    transform(chunk, enc, cb) {
      rawBytes += chunk.length;
      const now = Date.now();
      lastDataAt = now;

      // ASCII scan (latin1 keeps bytes 1:1) for object + completion markers.
      const str = chunk.toString('latin1');
      let s;
      s = scan(tCarry, str, TABLE_NEEDLE); tableCount += s.n; tCarry = s.carry;
      s = scan(vCarry, str, VIEW_NEEDLE); viewCount += s.n; vCarry = s.carry;
      endTail = (endTail + str).slice(-64); // enough to hold the trailer line

      if (!connected) {
        connected = true;
        lastProgressAt = now;
        logEvent('info', 'backup', `Connected to ${c.host}:${c.port} — receiving data…`, { trigger });
        startWatchdog();
      } else if (now - lastProgressAt >= PROGRESS_LOG_MS) {
        const delta = rawBytes - lastLoggedBytes;
        lastProgressAt = now;
        lastLoggedBytes = rawBytes;
        logEvent('info', 'backup', `Dumping "${c.database}"… ${humanBytes(rawBytes)} (+${humanBytes(delta)}, ${tableCount} tables so far)`, { trigger, bytes: rawBytes });
      }
      cb(null, chunk);
    },
  });

  return {
    stream,
    bytes: () => rawBytes,
    connected: () => connected,
    tables: () => tableCount,
    views: () => viewCount,
    completed: () => endTail.includes(DONE_MARKER),
    stop: () => { if (watchdog) clearInterval(watchdog); watchdog = null; },
  };
}

// Read a finished .sql.gz back and count what's actually in it — lets the panel
// verify any existing backup on demand (streaming gunzip, low memory).
function inspectBackup(full) {
  return new Promise((resolve, reject) => {
    let tables = 0, views = 0, bytes = 0;
    let tCarry = '', vCarry = '', endTail = '';
    const rs = fs.createReadStream(full);
    const gunzip = zlib.createGunzip();
    rs.on('error', reject);
    gunzip.on('error', reject);
    gunzip.on('data', (chunk) => {
      bytes += chunk.length;
      const str = chunk.toString('latin1');
      let s;
      s = scan(tCarry, str, TABLE_NEEDLE); tables += s.n; tCarry = s.carry;
      s = scan(vCarry, str, VIEW_NEEDLE); views += s.n; vCarry = s.carry;
      endTail = (endTail + str).slice(-64);
    });
    gunzip.on('end', () => resolve({ tables, views, complete: endTail.includes(DONE_MARKER), uncompressedBytes: bytes }));
    rs.pipe(gunzip);
  });
}

// Build the mysqldump invocation(s) for a backup.
//   mode 'full'  -> one pass, everything including log-table rows.
//   mode 'data'  -> two passes: everything EXCEPT the log tables' rows, then a
//                   structure-only pass for the log tables. The log tables still
//                   exist after a restore (so the app works), but the frequent
//                   backups don't carry millions of log rows.
// Database-level objects (routines/events) go in the first pass only, so they
// aren't emitted twice and can't collide on import.
function buildDumpPasses(c, cnfPath, mode, logTables) {
  const base = [
    `--defaults-extra-file=${cnfPath}`,
    '--single-transaction', // consistent snapshot, no table locks (InnoDB)
    '--quick',              // stream rows, low memory
    '--triggers',
    '--no-tablespaces',     // avoids needing the PROCESS privilege
    '--default-character-set=utf8mb4',
  ];
  if (DUMP_EXTRA_ARGS) base.push(...DUMP_EXTRA_ARGS.split(/\s+/));
  const dbLevel = ['--routines', '--events'];

  // Positional db name (NOT --databases) keeps the dump portable: no
  // `CREATE DATABASE`/`USE`, so it imports into whichever DB you select.
  if (mode === 'full' || !logTables.length) {
    return [[...base, ...dbLevel, c.database]];
  }
  return [
    [...base, ...dbLevel, ...logTables.map((t) => `--ignore-table=${c.database}.${t}`), c.database],
    [...base, '--no-data', c.database, ...logTables],
  ];
}

// Run dump passes one after another, streaming each one's stdout into `dest`
// (without ending it) so the passes concatenate into a single SQL file.
function runDumpPasses(bin, passes, dest, hooks = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let i = 0;
    const next = () => {
      if (i >= passes.length) return finish({ ok: true });
      const child = spawn(bin, passes[i++], { stdio: ['ignore', 'pipe', 'pipe'] });
      if (hooks.onChild) hooks.onChild(child);
      let closed = false, ended = false, code = null;
      child.stderr.on('data', (d) => hooks.onStderr && hooks.onStderr(d.toString()));
      child.on('error', (err) => finish({ ok: false, spawnErr: err }));
      child.stdout.on('end', () => { ended = true; maybe(); });
      child.on('close', (cd) => { code = cd; closed = true; maybe(); });
      child.stdout.pipe(dest, { end: false });
      function maybe() {
        if (!closed || !ended) return;
        if (code !== 0) return finish({ ok: false, code });
        next(); // ordering is safe: this pass's stdout has fully drained
      }
    };
    next();
  });
}

function runBackup(trigger = 'schedule', mode = 'full') {
  return new Promise((resolve) => {
    // Log every failure to the console (except a harmless "already running" overlap).
    const failEarly = (error) => {
      state.lastRun = Date.now();
      state.lastResult = { ok: false, error, trigger, mode, at: state.lastRun };
      logEvent('error', 'backup', `Backup failed (${trigger}/${mode}): ${error}`, { trigger, mode });
      resolve({ ok: false, error });
    };

    if (state.running) return resolve({ ok: false, error: 'A backup is already running' });
    const conn = getConnectionString();
    if (!conn) return failEarly('No connection string configured');

    let c;
    try { c = parseMysqlConn(conn); }
    catch (e) { return failEarly(e.message); }

    const bin = resolveDumpBin();
    if (!bin) {
      return failEarly('mysqldump / mariadb-dump not found on server (install a MySQL client)');
    }

    const logTables = config.logTables || [];
    // With no log tables configured there's nothing to skip, so every backup is full.
    const kind = (mode === 'data' && logTables.length) ? 'data' : 'full';

    state.running = true;
    const startedAt = Date.now();
    const scope = kind === 'data'
      ? `skipping rows of ${logTables.length} log table(s)`
      : 'everything incl. log tables';
    logEvent('info', 'backup', `Starting ${trigger} ${kind} backup of "${c.database}" @ ${c.host}:${c.port} — ${scope}`, { trigger, mode: kind });

    const finalName = timestampName(kind);
    const finalPath = path.join(BACKUP_DIR, finalName);
    const tmpPath = finalPath + '.partial';

    let cnfPath;
    try { cnfPath = writeDefaultsFile(c); }
    catch (e) { state.running = false; return failEarly('Could not prepare credentials: ' + e.message); }

    const passes = buildDumpPasses(c, cnfPath, kind, logTables);
    const gzip = zlib.createGzip();
    const out = fs.createWriteStream(tmpPath, { mode: 0o600 });

    let stderr = '';
    let passResult = null;
    let streamErr = null;
    let doneChild = false;
    let doneStream = false;
    let timedOut = false;
    let currentChild = null;

    // Watch the dump stream to log connection + progress. The first byte on
    // stdout means the server accepted us and the dump is streaming — a clean
    // "we connected OK" signal, distinct from an auth/connection error.
    const prog = makeDumpProgress(c, trigger);

    // Abort a dump that runs too long, so a hung connection can't wedge the
    // engine (state.running) permanently.
    const killTimer = setTimeout(() => {
      timedOut = true;
      logEvent('error', 'backup', `Backup exceeded ${MAX_DUMP_MIN} min — aborting (set DUMP_TIMEOUT_MIN to change)`, { trigger });
      try { if (currentChild) currentChild.kill('SIGKILL'); } catch {}
    }, MAX_DUMP_MIN * 60 * 1000);
    if (killTimer.unref) killTimer.unref();

    // Downstream stays constant while each pass feeds into prog.stream.
    pipeline(prog.stream, gzip, out, (err) => { streamErr = err || null; doneStream = true; maybeFinish(); });

    runDumpPasses(bin, passes, prog.stream, {
      onChild: (ch) => { currentChild = ch; },
      onStderr: (s) => { stderr += s; if (stderr.length > 8000) stderr = stderr.slice(-8000); },
    }).then((r) => {
      passResult = r;
      if (r.ok) logEvent('info', 'backup', `Dump complete (${humanBytes(prog.bytes())}) — compressing & saving…`, { trigger, bytes: prog.bytes() });
      prog.stream.end(); // closes gzip -> out, completing the pipeline
      doneChild = true;
      maybeFinish();
    });

    function maybeFinish() {
      if (!doneChild || !doneStream) return;
      state.running = false;
      clearTimeout(killTimer);
      prog.stop();
      try { if (cnfPath) fs.unlinkSync(cnfPath); } catch {}

      const failed = !passResult || !passResult.ok || streamErr;
      if (failed) {
        try { fs.unlinkSync(tmpPath); } catch {}
        let error;
        if (timedOut) error = `Timed out after ${MAX_DUMP_MIN} min and was aborted`;
        else if (passResult && passResult.spawnErr) error = passResult.spawnErr.message;
        else if (streamErr) error = 'Failed writing backup: ' + streamErr.message;
        else {
          const detail = cleanDumpError(stderr) || `dump exited with code ${passResult && passResult.code}`;
          // No stdout at all => it never got past connecting / the opening query.
          error = prog.connected() ? detail : `Never received data (connection, auth, or database problem) — ${detail}`;
        }
        return finish({ ok: false, error });
      }
      try {
        fs.renameSync(tmpPath, finalPath);
        const size = fs.statSync(finalPath).size;

        // Surface anything mysqldump complained about, even though it exited 0 —
        // this is how a "successful" dump can quietly skip a view/table.
        const warns = meaningfulStderrLines(stderr);
        if (warns.length) {
          logEvent('warn', 'backup', `mysqldump reported: ${warns.slice(-6).join(' | ')}`, { trigger });
        }
        // The completion marker is our proof the dump wasn't truncated.
        if (!prog.completed()) {
          logEvent('warn', 'backup', `Dump has no "${DONE_MARKER}" marker — it may be incomplete. Verify the table count.`, { trigger });
        }
        finish({ ok: true, name: finalName, size, kind, tables: prog.tables(), views: prog.views(), complete: prog.completed() });
      } catch (e) {
        try { fs.unlinkSync(tmpPath); } catch {}
        finish({ ok: false, error: 'Backup finished but could not be saved: ' + e.message });
      }
    }

    function finish(result) {
      state.lastRun = Date.now();
      state.lastResult = { ...result, trigger, mode: kind, at: state.lastRun };
      if (result.ok) {
        const secs = ((state.lastRun - startedAt) / 1000).toFixed(1);
        const extra = [`${result.tables} tables`];
        if (result.views) extra.push(`${result.views} views`);
        logEvent('success', 'backup', `${kind === 'data' ? 'Data' : 'Full'} backup saved: ${result.name} — ${humanBytes(result.size)}, ${extra.join(', ')}, in ${secs}s`, { name: result.name, size: result.size, tables: result.tables, views: result.views, kind, trigger, seconds: Number(secs) });
      } else {
        logEvent('error', 'backup', `Backup failed (${trigger}/${kind}): ${result.error}`, { trigger });
      }
      resolve(result);
    }
  });
}

// Meaningful stderr lines from the dump (drop the mariadb-dump deprecation notice).
function meaningfulStderrLines(stderr) {
  return stderr.split('\n').map((l) => l.trim()).filter(Boolean)
    .filter((l) => !/deprecated/i.test(l));
}
function cleanDumpError(stderr) {
  const lines = meaningfulStderrLines(stderr);
  return lines[lines.length - 1] || '';
}

// Minimum gap between two backup starts when a run overruns its own interval.
const MIN_GAP_MS = 30 * 1000;

// Delay until the NEXT start, so the cadence is start-to-start: a 30-minute
// interval means a backup begins every 30 minutes, regardless of how long the
// dump itself takes. (Waiting a full interval *after* the dump finished made
// the real gap "interval + dump time" — e.g. 30 min set, ~40 min actual.)
function nextDelayMs(intervalMs, elapsedMs) {
  return Math.max(MIN_GAP_MS, intervalMs - elapsedMs);
}

// Bumped on every schedule() call so an in-flight run from an older schedule
// can't re-arm itself and clobber a newly-saved interval.
let scheduleGen = 0;

// Two independent schedules: frequent "data" backups (log rows skipped) and a
// rare "full" backup that includes the log tables' rows.
function schedule() {
  scheduleGen++;
  const gen = scheduleGen;
  for (const k of Object.keys(timers)) {
    if (timers[k]) clearTimeout(timers[k]);
    timers[k] = null;
  }
  state.nextRunAt = null;
  state.nextFullRunAt = null;
  if (!config.connectionEnc) return;

  armKind('data', gen);
  // Only worth a separate full schedule when some tables are actually skipped.
  if ((config.logTables || []).length) armKind('full', gen);
}

function minutesFor(kind) {
  return kind === 'full' ? config.fullIntervalMinutes : config.intervalMinutes;
}

function armKind(kind, gen) {
  const initialMin = minutesFor(kind);
  if (!initialMin || initialMin <= 0) return;

  const arm = (delayMs) => {
    const at = Date.now() + delayMs;
    if (kind === 'full') state.nextFullRunAt = at; else state.nextRunAt = at;
    timers[kind] = setTimeout(async () => {
      if (gen !== scheduleGen) return;          // superseded by a newer schedule()
      const startedAt = Date.now();
      await runBackup('schedule', kind);
      if (gen !== scheduleGen) return;          // interval changed while running
      // Re-read the interval every cycle so changes apply immediately.
      const mins = minutesFor(kind);
      const intervalMs = mins * 60 * 1000;
      const elapsed = Date.now() - startedAt;
      if (elapsed > intervalMs) {
        logEvent('warn', 'schedule', `${kind} backup took ${Math.round(elapsed / 60000)} min — longer than the ${mins} min interval. Consider a longer interval.`);
      }
      arm(nextDelayMs(intervalMs, elapsed));
    }, delayMs);
  };

  arm(initialMin * 60 * 1000);
}

// ---------------------------------------------------------------------------
// Backup file helpers (with path-traversal protection)
// ---------------------------------------------------------------------------
function listBackups() {
  let names;
  try { names = fs.readdirSync(BACKUP_DIR); } catch { return []; }
  return names
    .filter((n) => n.endsWith(BACKUP_EXT))
    .map((n) => {
      const st = fs.statSync(path.join(BACKUP_DIR, n));
      return { name: n, size: st.size, createdAt: st.mtimeMs };
    })
    .sort((a, b) => b.createdAt - a.createdAt);
}

function resolveBackup(name) {
  // Only accept a bare filename that exists in BACKUP_DIR and ends with BACKUP_EXT.
  if (typeof name !== 'string') return null;
  const base = path.basename(name);
  if (base !== name || !base.endsWith(BACKUP_EXT)) return null;
  const full = path.join(BACKUP_DIR, base);
  if (path.dirname(full) !== BACKUP_DIR) return null;
  if (!fs.existsSync(full)) return null;
  return full;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.disable('x-powered-by');
// Number of reverse-proxy hops to trust for req.ip (used by the login rate limit).
// 1 suits Railway / a single reverse proxy. Set TRUST_PROXY=0 when clients connect
// directly, otherwise a spoofed X-Forwarded-For header could dodge the limit.
app.set('trust proxy', parseInt(process.env.TRUST_PROXY ?? '1', 10) || false);
app.use(express.json({ limit: '64kb' }));

// Security headers on every response.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// --- login rate limiting (in-memory) ---
const loginAttempts = new Map(); // ip -> { count, first }
function rateLimited(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec) return false;
  if (now - rec.first > 15 * 60 * 1000) { loginAttempts.delete(ip); return false; }
  return rec.count >= 10;
}
function noteAttempt(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (!rec || now - rec.first > 15 * 60 * 1000) loginAttempts.set(ip, { count: 1, first: now });
  else rec.count++;
  // Drop expired entries so the map can't grow without bound.
  if (loginAttempts.size > 10000) {
    for (const [k, r] of loginAttempts) if (now - r.first > 15 * 60 * 1000) loginAttempts.delete(k);
  }
}

// --- cookie helpers ---
function setSessionCookie(res, token) {
  const parts = [
    `sess=${token}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Strict',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (COOKIE_SECURE) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearSessionCookie(res) {
  const parts = ['sess=', 'HttpOnly', 'Path=/', 'SameSite=Strict', 'Max-Age=0'];
  if (COOKIE_SECURE) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const pair of raw.split(';')) {
    const i = pair.indexOf('=');
    if (i === -1) continue;
    out[pair.slice(0, i).trim()] = pair.slice(i + 1).trim();
  }
  return out;
}

function getSession(req) {
  return verifySession(parseCookies(req).sess);
}

function requireAuth(req, res, next) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  // CSRF: mutating requests must echo the token bound to this session.
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (!session.csrf || !safeEqual(req.get('x-csrf-token') || '', session.csrf)) {
      return res.status(403).json({ error: 'Bad CSRF token' });
    }
  }
  req.session = session;
  next();
}

// --- health check ---
app.get('/health', (req, res) => res.status(200).send('ok'));

// --- panel (with per-request CSP nonce) ---
const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
app.get('/', (req, res) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Content-Security-Policy',
    `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; ` +
    `img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(INDEX_HTML.replace(/__NONCE__/g, nonce));
});

// --- auth endpoints ---
app.post('/api/login', (req, res) => {
  const ip = req.ip || 'unknown';
  if (rateLimited(ip)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  const password = (req.body && req.body.password) || '';
  if (!safeEqual(password, APP_PASSWORD)) {
    noteAttempt(ip);
    logEvent('error', 'auth', `Failed login attempt from ${ip}`, { ip });
    return res.status(401).json({ error: 'Wrong password' });
  }
  loginAttempts.delete(ip);
  const csrf = crypto.randomBytes(16).toString('hex');
  const token = signSession({ csrf, exp: Date.now() + SESSION_TTL_MS });
  setSessionCookie(res, token);
  logEvent('info', 'auth', `Signed in from ${ip}`, { ip });
  res.json({ ok: true, csrf });
});

app.post('/api/logout', (req, res) => {
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const session = getSession(req);
  if (!session) return res.json({ authenticated: false });
  res.json({ authenticated: true, csrf: session.csrf });
});

// --- settings ---
app.get('/api/settings', requireAuth, (req, res) => {
  res.json({
    configured: !!config.connectionEnc,
    intervalMinutes: config.intervalMinutes,
    logTables: config.logTables,
    fullIntervalMinutes: config.fullIntervalMinutes,
    updatedAt: config.updatedAt,
  });
});

app.post('/api/settings', requireAuth, (req, res) => {
  const body = req.body || {};
  let changed = false;
  const logs = [];

  if (typeof body.connectionString === 'string' && body.connectionString.trim()) {
    const conn = body.connectionString.trim();
    let parsed;
    try { parsed = parseMysqlConn(conn); } // validate format before storing
    catch (e) { return res.status(400).json({ error: e.message }); }
    config.connectionEnc = encryptSecret(conn);
    changed = true;
    logs.push(['info', 'settings', `Connection string updated (db "${parsed.database}" @ ${parsed.host})`]);
  }
  if (body.clearConnection === true) {
    config.connectionEnc = null;
    changed = true;
    logs.push(['info', 'settings', 'Connection string removed — auto-backups disabled']);
  }
  if (body.intervalMinutes !== undefined) {
    const prev = config.intervalMinutes;
    config.intervalMinutes = clampInterval(body.intervalMinutes);
    if (config.intervalMinutes !== prev) {
      changed = true;
      logs.push(['info', 'settings', `Auto-backup interval set to ${config.intervalMinutes} min`]);
    }
  }
  if (body.fullIntervalMinutes !== undefined) {
    const prev = config.fullIntervalMinutes;
    config.fullIntervalMinutes = clampInterval(body.fullIntervalMinutes);
    if (config.fullIntervalMinutes !== prev) {
      changed = true;
      logs.push(['info', 'settings', `Full backup interval set to ${config.fullIntervalMinutes} min`]);
    }
  }
  if (body.logTables !== undefined) {
    const prev = (config.logTables || []).join(',');
    config.logTables = parseTableList(body.logTables);
    if (config.logTables.join(',') !== prev) {
      changed = true;
      logs.push(['info', 'settings', config.logTables.length
        ? `Log tables (rows skipped in frequent backups): ${config.logTables.join(', ')}`
        : 'Log-table list cleared — every backup is now full']);
    }
  }
  if (changed) {
    config.updatedAt = Date.now();
    saveConfig();
    schedule();
    for (const [lvl, ev, msg] of logs) logEvent(lvl, ev, msg);
  }
  res.json({
    ok: true,
    configured: !!config.connectionEnc,
    intervalMinutes: config.intervalMinutes,
    fullIntervalMinutes: config.fullIntervalMinutes,
    logTables: config.logTables,
  });
});

// --- status ---
app.get('/api/status', requireAuth, (req, res) => {
  const backups = listBackups();
  const totalSize = backups.reduce((s, b) => s + b.size, 0);
  res.json({
    running: state.running,
    lastRun: state.lastRun,
    lastResult: state.lastResult,
    nextRunAt: state.nextRunAt,
    nextFullRunAt: state.nextFullRunAt,
    intervalMinutes: config.intervalMinutes,
    fullIntervalMinutes: config.fullIntervalMinutes,
    logTables: config.logTables,
    configured: !!config.connectionEnc,
    count: backups.length,
    totalSize,
  });
});

// --- backups ---
app.get('/api/backups', requireAuth, (req, res) => {
  res.json({ backups: listBackups() });
});

app.post('/api/backup/run', requireAuth, async (req, res) => {
  const mode = (req.body && req.body.mode) === 'data' ? 'data' : 'full';
  const result = await runBackup('manual', mode);
  if (result.ok) res.json(result);
  else res.status(400).json(result);
});

app.get('/api/backups/file/:name', requireAuth, (req, res) => {
  const full = resolveBackup(req.params.name);
  if (!full) return res.status(404).json({ error: 'Not found' });
  res.download(full, path.basename(full));
});

// Download the raw, uncompressed SQL (decompressed on the fly — the exact bytes
// mysqldump produced; gzip is lossless so nothing is altered).
app.get('/api/backups/raw/:name', requireAuth, (req, res) => {
  const full = resolveBackup(req.params.name);
  if (!full) return res.status(404).json({ error: 'Not found' });
  const rawName = path.basename(full).replace(/\.gz$/, ''); // backup_….sql
  res.setHeader('Content-Type', 'application/sql; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${rawName}"`);
  const rs = fs.createReadStream(full);
  const gunzip = zlib.createGunzip();
  const bail = () => { try { res.destroy(); } catch {} };
  rs.on('error', bail);
  gunzip.on('error', bail);
  rs.pipe(gunzip).pipe(res);
});

// Verify what's actually inside a stored backup (counts objects in the .sql.gz).
app.get('/api/backups/inspect/:name', requireAuth, async (req, res) => {
  const full = resolveBackup(req.params.name);
  if (!full) return res.status(404).json({ error: 'Not found' });
  try {
    const info = await inspectBackup(full);
    res.json(info);
  } catch (e) {
    res.status(500).json({ error: 'Could not read backup: ' + e.message });
  }
});

app.post('/api/backups/delete', requireAuth, (req, res) => {
  const names = Array.isArray(req.body && req.body.names) ? req.body.names : [];
  let deleted = 0;
  let freed = 0;
  const errors = [];
  for (const name of names) {
    const full = resolveBackup(name);
    if (!full) { errors.push(name); continue; }
    try { const sz = fs.statSync(full).size; fs.unlinkSync(full); deleted++; freed += sz; } catch { errors.push(name); }
  }
  if (deleted) logEvent('info', 'delete', `Deleted ${deleted} backup(s), freed ${humanBytes(freed)}`, { deleted, freed });
  res.json({ ok: true, deleted, errors });
});

app.post('/api/backups/download', requireAuth, (req, res) => {
  const names = Array.isArray(req.body && req.body.names) ? req.body.names : [];
  const files = names.map(resolveBackup).filter(Boolean);
  if (!files.length) return res.status(400).json({ error: 'No valid backups selected' });

  const stamp = new Date().toISOString().slice(0, 10);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="backups_${stamp}.zip"`);

  // Files are already gzip-compressed, so store without recompressing.
  const archive = archiver('zip', { store: true });
  archive.on('error', () => { try { res.destroy(); } catch {} });
  archive.pipe(res);
  for (const full of files) archive.file(full, { name: path.basename(full) });
  archive.finalize();
  logEvent('info', 'download', `Downloaded ${files.length} backup(s) as ZIP`, { count: files.length });
});

// --- activity console (the persistent log) ---
app.get('/api/activity', requireAuth, (req, res) => {
  res.json(readActivity(req.query.limit));
});

app.get('/api/activity/download', requireAuth, (req, res) => {
  if (!fs.existsSync(ACTIVITY_FILE)) return res.status(404).json({ error: 'No activity yet' });
  res.download(ACTIVITY_FILE, 'db-backuper-activity.log');
});

// ---------------------------------------------------------------------------
// Boot (only when run directly, so the internals can be unit-tested)
// ---------------------------------------------------------------------------
if (require.main === module) {
  loadConfig();
  schedule();
  http.createServer(app).listen(PORT, BIND_HOST, () => {
    console.log(`[db-backuper] listening on ${BIND_HOST}:${PORT}  (interval ${config.intervalMinutes}m, configured=${!!config.connectionEnc})`);
    logEvent('info', 'startup', `Server started — auto-backup ${config.connectionEnc && config.intervalMinutes > 0 ? `every ${config.intervalMinutes} min` : 'off'}`);
  });
}

module.exports = {
  parseMysqlConn, cnfQuote, writeDefaultsFile, encryptSecret, decryptSecret,
  timestampName, resolveBackup, BACKUP_EXT, logEvent, readActivity, humanBytes,
  makeDumpProgress, meaningfulStderrLines, cleanDumpError, inspectBackup, scan,
  nextDelayMs, MIN_GAP_MS, buildDumpPasses, runDumpPasses, parseTableList,
};
