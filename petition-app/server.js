/**
 * המצפן הלאומי — שרת Node.js (ללא תלויות חיצוניות)
 *
 * הפעלה מקומית:
 *   node server.js
 *
 * משתני סביבה אופציונליים:
 *   PORT              – ברירת מחדל 3000
 *   CRM_WEBHOOK_URL   – URL של Make/Zapier/CRM. אם מוגדר – כל ליד חדש נשלח אוטומטית
 *   SMS_WEBHOOK_URL   – URL לשליחת SMS (ראה sendSms למטה)
 *   COUNTER_OFFSET    – offset התחלתי למונה. ברירת מחדל 1500
 *   ADMIN_USER        – שם משתמש לאדמין. ברירת מחדל: admin
 *   ADMIN_PASS        – סיסמת אדמין. חובה להגדיר בפרודקשן!
 *   DATA_ENCRYPTION_KEY – מפתח הצפנה 64 hex chars (32 bytes). אם לא מוגדר – ניצור אוטומטית
 */

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PORT               = process.env.PORT || 3000;
const DATA_FILE          = path.join(__dirname, 'data', 'signatures.enc');
const DATA_FILE_LEGACY   = path.join(__dirname, 'data', 'signatures.json');
const PUBLIC_DIR         = path.join(__dirname, 'public');
const CRM_WEBHOOK_URL    = process.env.CRM_WEBHOOK_URL || '';
const SMS_WEBHOOK_URL    = process.env.SMS_WEBHOOK_URL || '';
const COUNTER_OFFSET     = parseInt(process.env.COUNTER_OFFSET || '1500', 10);
const TURNSTILE_SECRET   = process.env.TURNSTILE_SECRET_KEY || '';

// ─── Password hashing (scrypt, RFC 7914) ─────────────────────────────────────
// Format: scrypt$N$r$p$salt_hex$hash_hex
// scrypt is memory-hard, far slower to brute-force than SHA-256 or bcrypt.
function hashPassword(password, salt) {
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'hex');
  const key = crypto.scryptSync(password, saltBuf, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$16384$8$1$${saltBuf.toString('hex')}$${key.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
    const N = parseInt(parts[1], 10);
    const r = parseInt(parts[2], 10);
    const p = parseInt(parts[3], 10);
    const salt = Buffer.from(parts[4], 'hex');
    const expected = Buffer.from(parts[5], 'hex');
    const derived = crypto.scryptSync(password, salt, expected.length, { N, r, p, maxmem: 64 * 1024 * 1024 });
    return expected.length === derived.length && crypto.timingSafeEqual(derived, expected);
  } catch { return false; }
}

// ─── TOTP (RFC 6238) — Google Authenticator / Authy ─────────────────────────
const _b32alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substr(i, 5).padEnd(5, '0');
    out += _b32alpha[parseInt(chunk, 2)];
  }
  while (out.length % 8) out += '=';
  return out;
}

function base32Decode(s) {
  s = String(s).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = '';
  for (const c of s) {
    const v = _b32alpha.indexOf(c);
    if (v < 0) throw new Error('invalid base32');
    bits += v.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return Buffer.from(bytes);
}

function totpGenerate(secretB32, when = Date.now()) {
  const counter = Math.floor(when / 1000 / 30);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const key = base32Decode(secretB32);
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 |
                (hmac[offset + 1] & 0xff) << 16 |
                (hmac[offset + 2] & 0xff) << 8 |
                (hmac[offset + 3] & 0xff)) % 1000000;
  return code.toString().padStart(6, '0');
}

function totpVerify(token, secretB32, windowSize = 1) {
  const t = String(token || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(t)) return false;
  const now = Date.now();
  const tBuf = Buffer.from(t);
  for (let i = -windowSize; i <= windowSize; i++) {
    try {
      const expected = Buffer.from(totpGenerate(secretB32, now + i * 30000));
      if (tBuf.length === expected.length && crypto.timingSafeEqual(tBuf, expected)) return true;
    } catch { /* ignore */ }
  }
  return false;
}

// ─── Admin credentials ───────────────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER || 'admin';

// Prefer ADMIN_PASS_HASH (pre-hashed scrypt). Otherwise hash ADMIN_PASS at startup
// with a deterministic salt derived from ADMIN_USER (so repeated boots compare consistently).
// In production, always set ADMIN_PASS_HASH — never ship plaintext passwords in env vars.
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || (() => {
  const pass = process.env.ADMIN_PASS || 'MitzpanLeumi2026-xK9mQ2pL7nR4';
  const salt = crypto.createHash('sha256').update(ADMIN_USER + '|mitzpan-leumi-salt').digest().subarray(0, 16);
  return hashPassword(pass, salt);
})();

const ADMIN_TOTP_SECRET = (process.env.ADMIN_TOTP_SECRET || '').trim();
const STRICT_SESSION_IP = process.env.STRICT_SESSION_IP === 'true';

// ─── Audit log (append-only JSON-lines at data/admin-audit.log) ─────────────
const AUDIT_LOG = path.join(__dirname, 'data', 'admin-audit.log');
function auditLog(event, data = {}) {
  const entry = JSON.stringify({ ts: new Date().toISOString(), event, ...data });
  try { fs.appendFileSync(AUDIT_LOG, entry + '\n'); } catch {}
  try { console.log('[audit]', entry); } catch {}
}

// ─── Session management (in-memory, secure random tokens) ────────────────────
const _sessions = new Map(); // sessionId → { user, createdAt, lastActivity, ip, userAgent }
const SESSION_MAX_AGE = 4 * 60 * 60 * 1000;          // 4h absolute
const SESSION_IDLE_TIMEOUT = 30 * 60 * 1000;         // 30min idle

function createSession(user, ip, userAgent) {
  const id = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  _sessions.set(id, { user, createdAt: now, lastActivity: now, ip, userAgent });
  return id;
}

function validateSession(cookieHeader, reqIp) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(/(?:^|;\s*)admin_session=([a-f0-9]{64})/);
  if (!match) return null;
  const sess = _sessions.get(match[1]);
  if (!sess) return null;
  const now = Date.now();
  if (now - sess.createdAt > SESSION_MAX_AGE) {
    _sessions.delete(match[1]);
    auditLog('session_expired_absolute', { user: sess.user, ip: sess.ip });
    return null;
  }
  if (now - sess.lastActivity > SESSION_IDLE_TIMEOUT) {
    _sessions.delete(match[1]);
    auditLog('session_expired_idle', { user: sess.user, ip: sess.ip });
    return null;
  }
  // Optional IP binding — reject if IP changed since login
  if (STRICT_SESSION_IP && reqIp && sess.ip && reqIp !== sess.ip) {
    _sessions.delete(match[1]);
    auditLog('session_ip_mismatch', { user: sess.user, original_ip: sess.ip, new_ip: reqIp });
    return null;
  }
  sess.lastActivity = now;
  return sess;
}

function destroySession(cookieHeader) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(/(?:^|;\s*)admin_session=([a-f0-9]{64})/);
  if (!match) return null;
  const sess = _sessions.get(match[1]);
  _sessions.delete(match[1]);
  return sess || null;
}

// Purge expired sessions every 30 min
setInterval(() => {
  const now = Date.now();
  for (const [id, sess] of _sessions) {
    if (now - sess.createdAt > SESSION_MAX_AGE || now - sess.lastActivity > SESSION_IDLE_TIMEOUT) {
      _sessions.delete(id);
    }
  }
}, 30 * 60 * 1000);

// ─── AES-256-GCM encryption for data at rest ────────────────────────────────
const DATA_KEY_HEX = process.env.DATA_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const DATA_KEY     = Buffer.from(DATA_KEY_HEX, 'hex');

function encryptData(plaintext) {
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', DATA_KEY, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  // Format: iv(16) + tag(16) + ciphertext
  return Buffer.concat([iv, tag, enc]);
}

function decryptData(buffer) {
  if (buffer.length < 33) throw new Error('encrypted data too short');
  const iv  = buffer.subarray(0, 16);
  const tag = buffer.subarray(16, 32);
  const enc = buffer.subarray(32);
  const decipher = crypto.createDecipheriv('aes-256-gcm', DATA_KEY, iv);
  decipher.setAuthTag(tag);
  return decipher.update(enc, null, 'utf8') + decipher.final('utf8');
}

// Keep ADMIN_TOKEN for backward compat (export endpoints) but deprecate URL-based admin access
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || crypto.randomBytes(12).toString('hex');

// ─── Rate limiting (in-memory, 5 req / 15 min per IP) ────────────────────────
const RATE_LIMIT_MAX    = 5;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes in ms
const _rateLimitMap     = new Map(); // ip → { count, resetAt }

function checkRateLimit(ip) {
  const now  = Date.now();
  const rec  = _rateLimitMap.get(ip);
  if (!rec || now > rec.resetAt) {
    _rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (rec.count >= RATE_LIMIT_MAX) return false;
  rec.count++;
  return true;
}

// ─── Admin rate limiting (3 attempts / hour per IP) ─────────────────────────
const ADMIN_RATE_LIMIT_MAX    = 3;
const ADMIN_RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour
function checkAdminRateLimit(ip) {
  const now = Date.now();
  const key = `admin_${ip}`;
  const rec = _rateLimitMap.get(key);
  if (!rec || now > rec.resetAt) {
    _rateLimitMap.set(key, { count: 1, resetAt: now + ADMIN_RATE_LIMIT_WINDOW });
    return true;
  }
  if (rec.count >= ADMIN_RATE_LIMIT_MAX) return false;
  rec.count++;
  return true;
}

// Purge stale entries every 30 minutes to avoid unbounded growth
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of _rateLimitMap) {
    if (now > rec.resetAt) _rateLimitMap.delete(ip);
  }
}, 30 * 60 * 1000);

// ─── Cloudflare Turnstile verification (skeleton) ────────────────────────────
/**
 * verifyTurnstile(token) → Promise<boolean>
 *
 * כדי להפעיל: הגדירו את משתנה הסביבה TURNSTILE_SECRET_KEY עם ה-secret key
 * מלוח הבקרה של Cloudflare Turnstile.
 * בצד הלקוח יש להוסיף את ווידג'ט ה-Turnstile ולשלוח את ה-token בשדה "cf-turnstile-response".
 * אם TURNSTILE_SECRET_KEY לא מוגדר – הפונקציה מחזירה true (מצב פיתוח/ביתא).
 */
function verifyTurnstile(token) {
  if (!TURNSTILE_SECRET) return Promise.resolve(true); // key not set → skip check
  return new Promise((resolve) => {
    const body = JSON.stringify({
      secret:   TURNSTILE_SECRET,
      response: token || '',
    });
    const req = require('https').request({
      method:   'POST',
      hostname: 'challenges.cloudflare.com',
      port:     443,
      path:     '/turnstile/v0/siteverify',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        try {
          const data = JSON.parse(raw);
          resolve(!!data.success);
        } catch { resolve(false); }
      });
    });
    req.on('error', () => resolve(false));
    req.write(body);
    req.end();
  });
}

// יעדי התקדמות: 10,000 → 25,000 → 50,000 → 100,000
const TARGETS = [10000, 25000, 50000, 100000];

// ─── נתונים ──────────────────────────────────────────────────────────────────

function loadData() {
  try {
    const buf = fs.readFileSync(DATA_FILE);
    const json = decryptData(buf);
    return JSON.parse(json);
  } catch {
    return [];
  }
}

function saveData(arr) {
  const json = JSON.stringify(arr, null, 2);
  fs.writeFileSync(DATA_FILE, encryptData(json));
}

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));

// ─── Auto-migrate from unencrypted signatures.json → encrypted signatures.enc
if (fs.existsSync(DATA_FILE_LEGACY) && !fs.existsSync(DATA_FILE)) {
  try {
    const legacy = JSON.parse(fs.readFileSync(DATA_FILE_LEGACY, 'utf8'));
    saveData(legacy);
    // Securely wipe the old plaintext file
    const size = fs.statSync(DATA_FILE_LEGACY).size;
    fs.writeFileSync(DATA_FILE_LEGACY, crypto.randomBytes(size));
    fs.unlinkSync(DATA_FILE_LEGACY);
    console.log(`[migration] Encrypted ${legacy.length} signatures. Old plaintext file wiped.`);
  } catch (e) {
    console.error('[migration] Failed to migrate legacy data:', e.message);
  }
}
if (!fs.existsSync(DATA_FILE)) saveData([]);

function currentTarget(total) {
  for (const t of TARGETS) if (total < t) return t;
  return TARGETS[TARGETS.length - 1];
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png':  'image/png',
  '.webp': 'image/webp',
  '.ico':  'image/x-icon',
};

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type':  'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 1e5) reject(new Error('too large'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { reject(new Error('invalid json')); }
    });
    req.on('error', reject);
  });
}

function isValidEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }
function isValidPhone(p) { return /^0[0-9]{8,9}$/.test(p.replace(/[-\s]/g, '')); }

function csvCell(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  // Prevent CSV formula injection (=, +, -, @, TAB, CR)
  if (/^[=+\-@\t\r]/.test(s)) {
    return '"' + ("'" + s).replace(/"/g, '""') + '"';
  }
  if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ─── אינטגרציות חיצוניות (hooks) ─────────────────────────────────────────────
// הערה: אלו hooks גנריים שפועלים דרך Webhooks (Make.com / Zapier / n8n / CRM).
// להפעלה אמיתית - יש להגדיר את משתני הסביבה המתאימים לפני הפעלת השרת.

function postWebhook(url, payload) {
  if (!url) return;
  try {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? require('https') : require('http');
    const data = JSON.stringify(payload);
    const req = lib.request({
      method:   'POST',
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname + u.search,
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
    }, resp => {
      // מתעלמים מתשובה - fire & forget
      resp.on('data', () => {});
    });
    req.on('error', err => console.error('[webhook]', url, err.message));
    req.write(data);
    req.end();
  } catch (e) {
    console.error('[webhook-error]', e.message);
  }
}

/**
 * שליחת SMS תודה אוטומטי.
 * הטקסט על פי ה-PRD: "תודה שהצטרפת אלינו למאבק על הדרך הלאומית-ליברלית..."
 *
 * להפעלה אמיתית: הגדירו SMS_WEBHOOK_URL שמפנה ל-Make/Zapier/Twilio Function
 * שמצפה ל-payload: { phone, text }
 */
function sendSms(phone, firstName) {
  if (!phone || !SMS_WEBHOOK_URL) return;
  const text =
    'תודה שהצטרפת אלינו למאבק על הדרך הלאומית-ליברלית. ' +
    'הדרך הזו היא העתיד של ישראל. דן אילוז.';
  postWebhook(SMS_WEBHOOK_URL, { phone, text, first_name: firstName });
}

// ─── Server ──────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const url    = req.url.split('?')[0];
  const method = req.method.toUpperCase();

  // ─── Security headers ─────────────────────────────────────────────────────
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  // ─── HTTPS enforcement (Render.com sets x-forwarded-proto) ────────────────
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] === 'http') {
    res.writeHead(301, { 'Location': 'https://' + req.headers.host + req.url });
    return res.end();
  }

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    });
    return res.end();
  }

  // ── API: POST /api/sign ───────────────────────────────────────────────────
  if (url === '/api/sign' && method === 'POST') {
    // Rate limiting
    const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (!checkRateLimit(clientIp)) {
      return sendJSON(res, 429, { error: 'יותר מדי בקשות. נסה שנית בעוד 15 דקות.' });
    }

    let body;
    try { body = await readBody(req); }
    catch { return sendJSON(res, 400, { error: 'בקשה שגויה' }); }

    // Turnstile verification
    const turnstileToken = String(body['cf-turnstile-response'] || '');
    const turnstileOk = await verifyTurnstile(turnstileToken);
    if (!turnstileOk) {
      return sendJSON(res, 403, { error: 'אימות אנטי-בוט נכשל. רעננו את הדף ונסו שנית.' });
    }

    // Sanitize: remove control chars, limit length
    const sanitize = (s, max = 100) => String(s || '').trim().replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').slice(0, max);
    const first_name = sanitize(body.first_name);
    const last_name  = sanitize(body.last_name);
    const phone      = sanitize(body.phone, 20);
    const email      = sanitize(body.email, 254);
    const consent    = !!body.consent;

    // ולידציות לפי ה-PRD
    if (first_name.length < 2)
      return sendJSON(res, 400, { error: 'יש להזין שם פרטי' });

    if (last_name.length < 1)
      return sendJSON(res, 400, { error: 'יש להזין שם משפחה' });

    if (!phone && !email)
      return sendJSON(res, 400, { error: 'יש להזין טלפון או אימייל (לפחות אחד)' });

    if (phone && !isValidPhone(phone))
      return sendJSON(res, 400, { error: 'מספר טלפון לא תקין' });

    if (email && !isValidEmail(email))
      return sendJSON(res, 400, { error: 'כתובת אימייל לא תקינה' });

    // Enforce consent server-side — required to contact user per privacy policy
    if (!consent)
      return sendJSON(res, 400, { error: 'יש לאשר קבלת עדכונים כדי להצטרף למצפן הלאומי' });

    const sigs = loadData();
    const phoneClean = phone.replace(/[-\s]/g, '');
    const emailLow   = email.toLowerCase();

    // מניעת כפילויות
    const exists = sigs.find(s =>
      (phoneClean && s.phone === phoneClean) ||
      (emailLow   && s.email === emailLow)
    );
    if (exists)
      return sendJSON(res, 409, { error: 'כבר חתמת על המצפן הלאומי! תודה שהצטרפת.' });

    const entry = {
      id:           Date.now(),
      first_name,
      last_name,
      last_initial: last_name.charAt(0),
      phone:        phoneClean,
      email:        emailLow,
      consent,
      source:       'minisite',
      created_at:   new Date().toISOString(),
    };
    sigs.push(entry);
    saveData(sigs);

    // אינטגרציות (fire & forget)
    postWebhook(CRM_WEBHOOK_URL, entry);
    sendSms(phoneClean, first_name);

    const total = sigs.length + COUNTER_OFFSET;
    return sendJSON(res, 200, {
      success: true,
      count:   total,
      target:  currentTarget(total),
    });
  }

  // ── API: GET /api/count ───────────────────────────────────────────────────
  if (url === '/api/count' && method === 'GET') {
    const sigs  = loadData();
    const total = sigs.length + COUNTER_OFFSET;
    return sendJSON(res, 200, { count: total, target: currentTarget(total) });
  }

  // ── API: GET /api/config (public, non-secret client config) ───────────────
  if (url === '/api/config' && method === 'GET') {
    return sendJSON(res, 200, {
      turnstileSiteKey: process.env.TURNSTILE_SITE_KEY || '',
    });
  }

  // ── API: POST /api/request-deletion (public, rate-limited) ────────────────
  // Users can request removal of their data (right-to-be-forgotten).
  // We don't auto-delete to prevent DoS abuse — we log the request and notify
  // the admin via webhook. Admin reviews and deletes via the dashboard.
  if (url === '/api/request-deletion' && method === 'POST') {
    const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (!checkRateLimit(clientIp)) {
      return sendJSON(res, 429, { error: 'יותר מדי בקשות. נסה שנית בעוד 15 דקות.' });
    }
    let body;
    try { body = await readBody(req); }
    catch { return sendJSON(res, 400, { error: 'בקשה שגויה' }); }

    const sanitize = (s, max = 100) => String(s || '').trim().replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').slice(0, max);
    const phone  = sanitize(body.phone, 20).replace(/[-\s]/g, '');
    const email  = sanitize(body.email, 254).toLowerCase();
    const reason = sanitize(body.reason, 500);

    if (!phone && !email)               return sendJSON(res, 400, { error: 'יש להזין טלפון או אימייל' });
    if (phone && !isValidPhone(phone))  return sendJSON(res, 400, { error: 'טלפון לא תקין' });
    if (email && !isValidEmail(email))  return sendJSON(res, 400, { error: 'אימייל לא תקין' });

    const request = {
      type:        'DELETION_REQUEST',
      phone, email, reason,
      received_at: new Date().toISOString(),
      ip:          clientIp,
    };
    postWebhook(CRM_WEBHOOK_URL, request);
    console.log('[deletion-request]', JSON.stringify(request));

    return sendJSON(res, 200, {
      success: true,
      message: 'בקשת ההסרה התקבלה. נטפל בה בתוך 7 ימים ונאשר לך במייל/סמס.',
    });
  }

  // ── ADMIN: Login page (GET /admin/login) ───────────────────────────────────
  if (url === '/admin/login' && method === 'GET') {
    const totpField = ADMIN_TOTP_SECRET ? `
    <label for="totp">קוד מאמת (Google Authenticator / Authy)</label>
    <input type="text" id="totp" name="totp" inputmode="numeric" pattern="\\d{6}" maxlength="6"
           placeholder="6 ספרות" autocomplete="one-time-code" required />` : '';
    const loginHtml = `<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>כניסת מנהל · המצפן הלאומי</title>
<style>
  body{font-family:Heebo,system-ui,sans-serif;margin:0;background:#0B1E3F;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}
  .card{background:#fff;color:#11223F;border-radius:16px;padding:40px;max-width:380px;width:90%;box-shadow:0 18px 48px rgba(0,0,0,0.35)}
  h1{font-size:1.4rem;margin-bottom:8px;text-align:center}
  .sub{color:#5A6A82;font-size:0.9rem;text-align:center;margin-bottom:28px}
  label{display:block;font-size:0.88rem;font-weight:600;margin-bottom:4px;margin-top:16px}
  input[type=text],input[type=password]{width:100%;padding:12px;border:1.5px solid #DDE3EC;border-radius:10px;font-size:1rem;font-family:inherit;box-sizing:border-box}
  input#totp{letter-spacing:0.25em;font-size:1.15rem;text-align:center;font-family:ui-monospace,Menlo,monospace}
  input:focus{outline:none;border-color:#D4A82A}
  button{width:100%;margin-top:24px;padding:14px;background:#D4A82A;color:#0B1E3F;border:none;border-radius:10px;font-size:1.05rem;font-weight:800;cursor:pointer;font-family:inherit}
  button:hover{background:#B88B15}
  .err{background:#FEE;border:1px solid #E88;color:#C33;padding:10px;border-radius:8px;margin-top:16px;text-align:center;font-size:0.9rem;display:none}
  .mfa-badge{margin-top:14px;padding:8px 12px;background:#EAFAF0;border:1px solid #B6E4C3;color:#15663B;border-radius:8px;text-align:center;font-size:0.82rem;font-weight:600}
</style>
<div class="card">
  <h1>🧭 המצפן הלאומי</h1>
  <p class="sub">כניסה לדשבורד ניהול</p>
  <form method="POST" action="/admin/login" autocomplete="on">
    <label for="user">שם משתמש</label>
    <input type="text" id="user" name="user" required autocomplete="username" />
    <label for="pass">סיסמה</label>
    <input type="password" id="pass" name="pass" required autocomplete="current-password" />${totpField}
    <button type="submit">כניסה</button>
  </form>
  ${ADMIN_TOTP_SECRET ? '<div class="mfa-badge">🛡️ אימות דו-שלבי מופעל</div>' : ''}
  <div class="err" id="err"></div>
</div>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(loginHtml);
  }

  // ── ADMIN: Login handler (POST /admin/login) ─────────────────────────────
  if (url === '/admin/login' && method === 'POST') {
    const adminIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const userAgent = String(req.headers['user-agent'] || '').slice(0, 200);

    if (!checkAdminRateLimit(adminIp)) {
      auditLog('login_rate_limited', { ip: adminIp, userAgent });
      res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!doctype html><meta charset=utf-8><div style="font-family:sans-serif;padding:40px;text-align:center;direction:rtl"><h2>יותר מדי ניסיונות</h2><p>נסו שנית בעוד שעה.</p></div>');
    }

    // Read raw body (form sends URL-encoded, not JSON)
    const raw = await new Promise((resolve, reject) => {
      let d = '';
      req.on('data', c => { d += c; if (d.length > 1e4) reject(new Error('too large')); });
      req.on('end', () => resolve(d));
      req.on('error', reject);
    }).catch(() => '');

    let user, pass, totp;
    try {
      const j = JSON.parse(raw);
      user = String(j.user || '');
      pass = String(j.pass || '');
      totp = String(j.totp || '');
    } catch {
      const params = new URLSearchParams(raw);
      user = params.get('user') || '';
      pass = params.get('pass') || '';
      totp = params.get('totp') || '';
    }

    const userOk = user === ADMIN_USER;
    const passOk = verifyPassword(pass, ADMIN_PASS_HASH);
    const totpOk = !ADMIN_TOTP_SECRET ? true : totpVerify(totp, ADMIN_TOTP_SECRET);

    // Determine specific failure reason (but don't reveal to attacker)
    let reason = 'ok';
    if (!userOk)      reason = 'bad_username';
    else if (!passOk) reason = 'bad_password';
    else if (!totpOk) reason = 'bad_totp';

    if (reason !== 'ok') {
      auditLog('login_failure', { ip: adminIp, user: user.slice(0, 40), reason, userAgent });
      const errMsg = (userOk && passOk && !totpOk)
        ? 'קוד האימות הדו-שלבי שגוי או פג תוקף'
        : 'שם משתמש או סיסמה שגויים';
      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>כניסה נכשלה</title>
<style>body{font-family:Heebo,sans-serif;background:#0B1E3F;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}
.card{background:#fff;color:#11223F;border-radius:16px;padding:40px;max-width:380px;width:90%;text-align:center}
a{color:#D4A82A;font-weight:700}</style>
<div class="card"><h2>${escapeHtml(errMsg)}</h2><p style="margin-top:16px"><a href="/admin/login">← נסו שנית</a></p></div>`);
    }

    const sessionId = createSession(user, adminIp, userAgent);
    auditLog('login_success', { ip: adminIp, user, userAgent, two_factor: !!ADMIN_TOTP_SECRET });
    const isSecure = req.headers['x-forwarded-proto'] === 'https';
    const cookieFlags = `HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE / 1000}${isSecure ? '; Secure' : ''}`;
    res.writeHead(302, {
      'Set-Cookie': `admin_session=${sessionId}; ${cookieFlags}`,
      'Location': '/admin',
    });
    return res.end();
  }

  // ── ADMIN: Logout (GET /admin/logout) ─────────────────────────────────────
  if (url === '/admin/logout' && method === 'GET') {
    const logoutIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const sess = destroySession(req.headers.cookie);
    if (sess) auditLog('logout', { ip: logoutIp, user: sess.user });
    res.writeHead(302, {
      'Set-Cookie': 'admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
      'Location': '/admin/login',
    });
    return res.end();
  }

  // ── ADMIN: Dashboard (GET /admin) — session-protected ─────────────────────
  if (url === '/admin' && method === 'GET') {
    const reqIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const session = validateSession(req.headers.cookie, reqIp);
    if (!session) {
      res.writeHead(302, { 'Location': '/admin/login' });
      return res.end();
    }
    const sigs = loadData();
    const total = sigs.length + COUNTER_OFFSET;
    const rows = sigs.slice().reverse().map(s => `
      <tr>
        <td>${s.id}</td>
        <td>${escapeHtml(s.first_name)} ${escapeHtml(s.last_name)}</td>
        <td>${escapeHtml(s.phone || '')}</td>
        <td>${escapeHtml(s.email || '')}</td>
        <td>${new Date(s.created_at).toLocaleString('he-IL')}</td>
        <td>
          <form method="POST" action="/admin/delete-signer" style="margin:0"
                onsubmit="return confirm('למחוק את ${escapeHtml(s.first_name)} ${escapeHtml(s.last_name)}? פעולה זו אינה הפיכה.')">
            <input type="hidden" name="id" value="${s.id}">
            <button type="submit" class="del-btn" title="מחק חתימה">מחק</button>
          </form>
        </td>
      </tr>`).join('');
    const html = `<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>אדמין · המצפן הלאומי</title>
<style>
  body{font-family:Heebo,system-ui,sans-serif;margin:0;background:#F2F4F8;color:#11223F}
  header{background:#0B1E3F;color:#fff;padding:20px 32px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
  header h1{font-size:1.3rem}
  .header-actions{display:flex;gap:16px;align-items:center}
  .header-actions a{color:#D4A82A;text-decoration:none;font-size:0.9rem}
  .header-actions .logout{color:#ff8a8a}
  .stats{display:flex;gap:20px;padding:24px 32px;flex-wrap:wrap}
  .stat{background:#fff;border:1px solid #DDE3EC;border-radius:12px;padding:18px 24px;min-width:180px}
  .stat .n{font-size:2rem;font-weight:900;color:#0B1E3F}
  .stat .l{color:#5A6A82;font-size:0.9rem;margin-top:4px}
  .actions{padding:0 32px 20px;display:flex;gap:12px;flex-wrap:wrap}
  .btn{background:#D4A82A;color:#0B1E3F;padding:10px 20px;border-radius:8px;font-weight:800;text-decoration:none;display:inline-block}
  .btn.ghost{background:#fff;border:1.5px solid #DDE3EC;color:#11223F}
  table{width:calc(100% - 64px);margin:0 32px 32px;background:#fff;border-collapse:collapse;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(11,30,63,0.08)}
  th{background:#0B1E3F;color:#fff;padding:12px;text-align:start;font-weight:700;font-size:0.9rem}
  td{padding:12px;border-top:1px solid #F2F4F8;font-size:0.92rem}
  tr:hover td{background:#FAFBFD}
  .del-btn{background:#C33;color:#fff;border:none;padding:6px 14px;border-radius:6px;font-size:0.82rem;cursor:pointer;font-weight:700;font-family:inherit}
  .del-btn:hover{background:#A02020}
  @media(max-width:600px){table{width:calc(100% - 32px);margin:0 16px 16px}td,th{padding:8px;font-size:0.82rem}}
</style>
<header>
  <h1>🧭 המצפן הלאומי · דשבורד אדמין</h1>
  <div class="header-actions">
    <span style="color:#BBC5D4;font-size:0.82rem">מחובר: ${escapeHtml(session.user)} · ${ADMIN_TOTP_SECRET ? '🛡️ 2FA' : '🔓 ללא 2FA'}</span>
    <a href="/admin/audit">📜 יומן ביקורת</a>
    <a href="/">↩ חזרה לאתר</a>
    <a href="/admin/logout" class="logout">🚪 התנתקות</a>
  </div>
</header>
<div class="stats">
  <div class="stat"><div class="n">${total.toLocaleString('he-IL')}</div><div class="l">סה"כ חתומים (כולל offset)</div></div>
  <div class="stat"><div class="n">${sigs.length.toLocaleString('he-IL')}</div><div class="l">חתימות אמיתיות במאגר</div></div>
  <div class="stat"><div class="n">${currentTarget(total).toLocaleString('he-IL')}</div><div class="l">היעד הנוכחי</div></div>
</div>
<div class="actions">
  <a class="btn" href="/api/export.csv">⬇ הורדת CSV (לאקסל)</a>
  <a class="btn ghost" href="/api/export.json">⬇ הורדת JSON</a>
</div>
<table>
  <thead><tr><th>ID</th><th>שם מלא</th><th>טלפון</th><th>אימייל</th><th>תאריך</th><th>פעולות</th></tr></thead>
  <tbody>${rows || '<tr><td colspan=6 style="text-align:center;color:#5A6A82;padding:40px">אין חתימות עדיין</td></tr>'}</tbody>
</table>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // ── ADMIN: GET /api/export.csv — session-protected ─────────────────────────
  if (url === '/api/export.csv' && method === 'GET') {
    const reqIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const sess = validateSession(req.headers.cookie, reqIp);
    if (!sess) {
      res.writeHead(302, { 'Location': '/admin/login' });
      return res.end();
    }
    auditLog('export_csv', { ip: reqIp, user: sess.user });
    const sigs = loadData();
    const header = ['id','first_name','last_name','phone','email','consent','source','created_at'];
    const csv = [header.join(',')].concat(
      sigs.map(s => header.map(h => csvCell(s[h])).join(','))
    ).join('\r\n');
    // BOM UTF-8 כדי שאקסל יפתח עברית נכון
    const body = '\ufeff' + csv;
    const fname = `signatures-${new Date().toISOString().slice(0,10)}.csv`;
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${fname}"`,
      'Cache-Control': 'no-store',
    });
    return res.end(body);
  }

  // ── ADMIN: POST /admin/delete-signer — session-protected ──────────────────
  // Accepts form-encoded { id } from dashboard delete button, or JSON { id }.
  // SameSite=Strict session cookie provides CSRF protection.
  if (url === '/admin/delete-signer' && method === 'POST') {
    const reqIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const sess = validateSession(req.headers.cookie, reqIp);
    if (!sess) {
      res.writeHead(302, { 'Location': '/admin/login' });
      return res.end();
    }

    const raw = await new Promise((resolve, reject) => {
      let d = '';
      req.on('data', c => { d += c; if (d.length > 1e4) reject(new Error('too large')); });
      req.on('end', () => resolve(d));
      req.on('error', reject);
    }).catch(() => '');

    let id = 0;
    try {
      const j = JSON.parse(raw);
      id = parseInt(j.id, 10) || 0;
    } catch {
      const params = new URLSearchParams(raw);
      id = parseInt(params.get('id') || '', 10) || 0;
    }

    if (!id) return sendJSON(res, 400, { error: 'invalid id' });

    const sigs     = loadData();
    const before   = sigs.length;
    const target   = sigs.find(s => s.id === id);
    const filtered = sigs.filter(s => s.id !== id);
    if (filtered.length === before) {
      const ct = String(req.headers.accept || '');
      if (ct.includes('application/json')) return sendJSON(res, 404, { error: 'לא נמצא' });
      res.writeHead(302, { 'Location': '/admin' });
      return res.end();
    }
    saveData(filtered);
    auditLog('delete_signer', {
      ip: reqIp,
      user: sess.user,
      signer_id: id,
      signer_name: target ? `${target.first_name} ${target.last_name}` : '(unknown)',
    });

    const ct = String(req.headers.accept || '');
    if (ct.includes('application/json')) return sendJSON(res, 200, { success: true });
    res.writeHead(302, { 'Location': '/admin' });
    return res.end();
  }

  // ── ADMIN: GET /api/export.json — session-protected ────────────────────────
  if (url === '/api/export.json' && method === 'GET') {
    const reqIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const sess = validateSession(req.headers.cookie, reqIp);
    if (!sess) {
      res.writeHead(302, { 'Location': '/admin/login' });
      return res.end();
    }
    auditLog('export_json', { ip: reqIp, user: sess.user });
    const sigs = loadData();
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="signatures.json"',
    });
    return res.end(JSON.stringify(sigs, null, 2));
  }

  // ── ADMIN: GET /admin/audit — session-protected audit log viewer ──────────
  if (url === '/admin/audit' && method === 'GET') {
    const reqIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const sess = validateSession(req.headers.cookie, reqIp);
    if (!sess) {
      res.writeHead(302, { 'Location': '/admin/login' });
      return res.end();
    }
    let entries = [];
    try {
      const raw = fs.readFileSync(AUDIT_LOG, 'utf8');
      entries = raw.split('\n').filter(Boolean).slice(-500).reverse().map(line => {
        try { return JSON.parse(line); } catch { return null; }
      }).filter(Boolean);
    } catch { /* no log yet */ }

    const eventBadge = (ev) => {
      const color = ev.startsWith('login_failure') || ev === 'session_ip_mismatch' ? '#C33' :
                    ev === 'login_success' ? '#15663B' :
                    ev === 'delete_signer' ? '#B88B15' : '#5A6A82';
      return `<span style="background:${color};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.78rem;font-weight:700">${escapeHtml(ev)}</span>`;
    };
    const rows = entries.map(e => `
      <tr>
        <td>${escapeHtml(e.ts || '')}</td>
        <td>${eventBadge(e.event || '')}</td>
        <td>${escapeHtml(e.user || '')}</td>
        <td>${escapeHtml(e.ip || '')}</td>
        <td style="font-size:0.82rem;color:#5A6A82">${escapeHtml(JSON.stringify(Object.fromEntries(Object.entries(e).filter(([k]) => !['ts','event','user','ip'].includes(k)))))}</td>
      </tr>`).join('');

    const html = `<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>יומן ביקורת · אדמין</title>
<style>
  body{font-family:Heebo,system-ui,sans-serif;margin:0;background:#F2F4F8;color:#11223F}
  header{background:#0B1E3F;color:#fff;padding:20px 32px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
  header h1{font-size:1.3rem}
  .header-actions a{color:#D4A82A;text-decoration:none;font-size:0.9rem;margin-inline-start:16px}
  table{width:calc(100% - 64px);margin:24px 32px;background:#fff;border-collapse:collapse;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(11,30,63,0.08)}
  th{background:#0B1E3F;color:#fff;padding:12px;text-align:start;font-weight:700;font-size:0.9rem}
  td{padding:10px;border-top:1px solid #F2F4F8;font-size:0.9rem;vertical-align:top}
  tr:hover td{background:#FAFBFD}
  .empty{text-align:center;color:#5A6A82;padding:40px}
  @media(max-width:800px){table{width:calc(100% - 32px);margin:16px}td,th{padding:8px;font-size:0.8rem}}
</style>
<header>
  <h1>📜 יומן ביקורת — 500 האירועים האחרונים</h1>
  <div class="header-actions">
    <a href="/admin">↩ חזרה לדשבורד</a>
    <a href="/admin/logout">🚪 התנתקות</a>
  </div>
</header>
<table>
  <thead><tr><th>תאריך/שעה</th><th>אירוע</th><th>משתמש</th><th>IP</th><th>פרטים</th></tr></thead>
  <tbody>${rows || '<tr><td colspan=5 class="empty">אין אירועים ביומן</td></tr>'}</tbody>
</table>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // ── API: GET /api/signers  (לטיקר החי) ────────────────────────────────────
  if (url === '/api/signers' && method === 'GET') {
    const sigs = loadData();
    const recent = sigs.slice().reverse().slice(0, 30).map(s => ({
      first_name:   escapeHtml(s.first_name),
      last_initial: escapeHtml(s.last_initial || (s.last_name ? s.last_name.charAt(0) : '')),
      created_at:   s.created_at,
    }));
    return sendJSON(res, 200, { signers: recent });
  }

  // ── קבצים סטטיים ──────────────────────────────────────────────────────────
  let filePath = path.join(PUBLIC_DIR, url === '/' ? 'index.html' : url);

  // הגנה מפני path-traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); return res.end('Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fallback ל-index.html
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (e2, d2) => {
        if (e2) { res.writeHead(404); return res.end('Not found'); }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(d2);
      });
      return;
    }
    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    const headers = { 'Content-Type': mime };
    // cache לתמונות
    if (['.jpg', '.jpeg', '.png', '.svg', '.webp', '.ico'].includes(ext)) {
      headers['Cache-Control'] = 'public, max-age=86400';
    }
    res.writeHead(200, headers);
    res.end(data);
  });
});

// ─── CLI helpers (run before starting the server) ───────────────────────────
// Usage:
//   node server.js --hash-password "my secret pass"   → prints ADMIN_PASS_HASH
//   node server.js --generate-totp                    → prints ADMIN_TOTP_SECRET + otpauth URL
if (process.argv.includes('--hash-password')) {
  const idx = process.argv.indexOf('--hash-password');
  const pass = process.argv[idx + 1];
  if (!pass) {
    console.error('\n❌  Usage: node server.js --hash-password "YOUR_STRONG_PASSWORD"\n');
    process.exit(1);
  }
  const salt = crypto.randomBytes(16);
  const hash = hashPassword(pass, salt);
  console.log('\n✅  Copy this into your Render environment:\n');
  console.log('ADMIN_PASS_HASH=' + hash);
  console.log('\nThen REMOVE the plaintext ADMIN_PASS env var from Render.\n');
  process.exit(0);
}

if (process.argv.includes('--generate-totp')) {
  const secret = base32Encode(crypto.randomBytes(20));
  const issuer = encodeURIComponent('המצפן הלאומי');
  const label = encodeURIComponent((ADMIN_USER || 'admin') + '@mitzpan-leumi');
  const otpauth = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&digits=6&period=30&algorithm=SHA1`;
  console.log('\n✅  Copy this into your Render environment:\n');
  console.log('ADMIN_TOTP_SECRET=' + secret);
  console.log('\nThen add the same secret to Google Authenticator / Authy by either:');
  console.log('  (a) scanning the QR code for this otpauth URL:');
  console.log('      ' + otpauth);
  console.log('  (b) typing the secret manually:');
  console.log('      ' + secret);
  console.log('\nAfter it\'s set, every admin login will require the current 6-digit code.\n');
  process.exit(0);
}

server.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════════════╗');
  console.log('║  ✅  המצפן הלאומי — השרת פעיל                  ║');
  console.log('╠════════════════════════════════════════════════╣');
  console.log(`  🌐 אתר ציבורי:   http://localhost:${PORT}/`);
  console.log(`  🔐 אדמין:        http://localhost:${PORT}/admin/login`);
  console.log(`  👤 משתמש:        ${ADMIN_USER}`);
  console.log('  🔒 נתונים:       AES-256-GCM מוצפנים');
  console.log('  🔑 סיסמה:        scrypt hashed' + (process.env.ADMIN_PASS_HASH ? '' : ' (derived from ADMIN_PASS)'));
  console.log(`  🛡  2FA (TOTP):   ${ADMIN_TOTP_SECRET ? 'פעיל' : 'כבוי — רצוי להפעיל'}`);
  console.log(`  🌐 IP binding:   ${STRICT_SESSION_IP ? 'פעיל' : 'כבוי'}`);
  if (!process.env.DATA_ENCRYPTION_KEY)
    console.log(`  ⚠️  DATA_ENCRYPTION_KEY לא הוגדר — נוצר מפתח אוטומטי: ${DATA_KEY_HEX}`);
  if (!process.env.ADMIN_PASS_HASH && !process.env.ADMIN_PASS)
    console.log('  ⚠️  לא הוגדרה סיסמת אדמין — משתמש בסיסמה ברירת מחדל');
  if (!ADMIN_TOTP_SECRET)
    console.log('  💡 להפעלת 2FA:   node server.js --generate-totp');
  if (!process.env.ADMIN_PASS_HASH)
    console.log('  💡 להצפנת סיסמה: node server.js --hash-password "YOUR_PASS"');
  if (CRM_WEBHOOK_URL) console.log('  🔗 CRM webhook: מחובר');
  if (SMS_WEBHOOK_URL) console.log('  📱 SMS webhook: מחובר');
  console.log('  Ctrl+C להפסקה');
  console.log('╚════════════════════════════════════════════════╝\n');
});
