/**
 * המצפן הלאומי — שרת Node.js (ללא תלויות חיצוניות)
 *
 * הפעלה מקומית:
 *   node server.js
 *
 * משתני סביבה אופציונליים:h
 *   PORT              – ברירת מחדל 3000
 *   CRM_WEBHOOK_URL   – URL של Make/Zapier/CRM. אם מוגדר – hכל ליד חדש נשלח אוטומטית
 *   SMS_WEBHOOK_URL   – URL לשליחת SMS (ראה sendSms למטה)
 *   COUNTER_OFFSET    – offset התחלתי למונה. ברירת מחדל 1500
 *   ADMIN_TOKEN       – טוקן לגישה לדשבורד האדמין ולייצוא CSV. אם לא מוגדר – ניצור אוטומטית
 */

const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT             = process.env.PORT || 3000;
const DATA_FILE        = path.join(__dirname, 'data', 'signatures.json');
const PUBLIC_DIR       = path.join(__dirname, 'public');
const CRM_WEBHOOK_URL  = process.env.CRM_WEBHOOK_URL || '';
const SMS_WEBHOOK_URL  = process.env.SMS_WEBHOOK_URL || '';
const COUNTER_OFFSET   = parseInt(process.env.COUNTER_OFFSET || '1500', 10);
const ADMIN_TOKEN      = process.env.ADMIN_TOKEN ||
  require('crypto').randomBytes(12).toString('hex');
const TURNSTILE_SECRET   = process.env.TURNSTILE_SECRET_KEY || '';

// ─── Rate limiting (in-memory, 5 req / 15 min per IP) ──────────────────────────────────────
const RATE_LIMIT_MAX    = 5;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 min
const _rateLimitMap     = new Map();
function checkRateLimit(ip) {
  const now = Date.now(), rec = _rateLimitMap.get(ip);
  if (!rec || now > rec.resetAt) {
    _rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (rec.count >= RATE_LIMIT_MAX) return false;
  rec.count++; return true;
}
setInterval(() => { const now = Date.now(); for (const [ip,rec] of _rateLimitMap) if (now > rec.resetAt) _rateLimitMap.delete(ip); }, 30*60*1000);

// ─── Cloudflare Turnstile verification (skeleton) ────────────────────────────
function verifyTurnstile(token) {
  if (!TURNSTILE_SECRET) return Promise.resolve(true);
  return new Promise((resolve) => {
    const body = JSON.stringify({ secret: TURNSTILE_SECRET, response: token || '' });
    const req = require('https').request({
      method: 'POST', hostname: 'challenges.cloudflare.com', port: 443,
      path: '/turnstile/v0/siteverify',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => { let raw = ''; res.on('data', c => raw += c); res.on('end', () => { try { resolve(!!JSON.parse(raw).success); } catch { resolve(false); } }); });
    req.on('error', () => resolve(false)); req.write(body); req.end();
  });
}


// יעדי התקדמות: 10,000 → 25,000 → 50,000 → 100,000
const TARGETS = [10000, 25000, 50000, 100000];

// ─── נתונים ──────────────────────────────────────────────────────────────────

function loadData() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return []; }
}

function saveData(arr) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(arr, null, 2), 'utf8');
}

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));
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
    const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (!checkRateLimit(clientIp)) return sendJSON(res, 429, { error: 'יותר מדי בקשות. נסה שנית בעוד 15 דקות.' });
    let body;
    try { body = await readBody(req); }
    catch { return sendJSON(res, 400, { error: 'בקשה שגויה' }); }

    const turnstileToken = String(body['cf-turnstile-response'] || '');
    const turnstileOk = await verifyTurnstile(turnstileToken);
    if (!turnstileOk) return sendJSON(res, 403, { error: 'אימות אנטי-בוט נכשל. רעננו את הדף ונסו שנית.' });

    const first_name = String(body.first_name || '').trim();
    const last_name  = String(body.last_name  || '').trim();
    const phone      = String(body.phone      || '').trim();
    const email      = String(body.email      || '').trim();
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
      consent:      true,
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

  // ── ADMIN: GET /admin?token=XXX  (דשבורד פשוט) ───────────────────────────
  if (url === '/admin' && method === 'GET') {
    const q = new URL(req.url, 'http://x').searchParams;
    if (q.get('token') !== ADMIN_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<!doctype html><meta charset=utf-8><div style="font-family:sans-serif;padding:40px;text-align:center"><h2>גישה נדחתה</h2><p>הוסיפו את הטוקן ל-URL: <code>/admin?token=YOUR_TOKEN</code></p></div>');
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
      </tr>`).join('');
    const html = `<!doctype html><html lang="he" dir="rtl"><meta charset="utf-8">
<title>אדמין · המצפן הלאומי</title>
<style>
  body{font-family:Heebo,system-ui,sans-serif;margin:0;background:#F2F4F8;color:#11223F}
  header{background:#0B1E3F;color:#fff;padding:20px 32px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
  header h1{font-size:1.3rem}
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
  @media(max-width:600px){table{width:calc(100% - 32px);margin:0 16px 16px}td,th{padding:8px;font-size:0.82rem}}
</style>
<header>
  <h1>🧭 המצפן הלאומי · דשבורד אדמין</h1>
  <a href="/" style="color:#D4A82A;text-decoration:none">↩ חזרה לאתר</a>
</header>
<div class="stats">
  <div class="stat"><div class="n">${total.toLocaleString('he-IL')}</div><div class="l">סה"כ חתומים (כולל offset)</div></div>
  <div class="stat"><div class="n">${sigs.length.toLocaleString('he-IL')}</div><div class="l">חתימות אמיתיות במאגר</div></div>
  <div class="stat"><div class="n">${currentTarget(total).toLocaleString('he-IL')}</div><div class="l">היעד הנוכחי</div></div>
</div>
<div class="actions">
  <a class="btn" href="/api/export.csv?token=${ADMIN_TOKEN}">⬇ הורדת CSV (לאקסל)</a>
  <a class="btn ghost" href="/api/export.json?token=${ADMIN_TOKEN}">⬇ הורדת JSON</a>
</div>
<table>
  <thead><tr><th>ID</th><th>שם מלא</th><th>טלפון</th><th>אימייל</th><th>תאריך</th></tr></thead>
  <tbody>${rows || '<tr><td colspan=5 style="text-align:center;color:#5A6A82;padding:40px">אין חתימות עדיין</td></tr>'}</tbody>
</table>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }

  // ── ADMIN: GET /api/export.csv?token=XXX  ─────────────────────────────────
  if (url === '/api/export.csv' && method === 'GET') {
    const q = new URL(req.url, 'http://x').searchParams;
    if (q.get('token') !== ADMIN_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'unauthorized' }));
    }
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

  // ── ADMIN: GET /api/export.json?token=XXX  ────────────────────────────────
  if (url === '/api/export.json' && method === 'GET') {
    const q = new URL(req.url, 'http://x').searchParams;
    if (q.get('token') !== ADMIN_TOKEN) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'unauthorized' }));
    }
    const sigs = loadData();
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="signatures.json"',
    });
    return res.end(JSON.stringify(sigs, null, 2));
  }

  // ── API: GET /api/signers  (לטיקר החי) ────────────────────────────────────
  if (url === '/api/signers' && method === 'GET') {
    const sigs = loadData();
    const recent = sigs.slice().reverse().slice(0, 30).map(s => ({
      first_name:   s.first_name,
      last_initial: s.last_initial || (s.last_name ? s.last_name.charAt(0) : ''),
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

server.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════════════╗');
  console.log('║  ✅  המצפן הלאומי — השרת פעיל                  ║');
  console.log('╠════════════════════════════════════════════════╣');
  console.log(`  🌐 אתר ציבורי:   http://localhost:${PORT}/`);
  console.log(`  🔐 אדמין:        http://localhost:${PORT}/admin?token=${ADMIN_TOKEN}`);
  console.log(`  📥 ייצוא CSV:    http://localhost:${PORT}/api/export.csv?token=${ADMIN_TOKEN}`);
  if (CRM_WEBHOOK_URL) console.log('  🔗 CRM webhook: מחובר');
  if (SMS_WEBHOOK_URL) console.log('  📱 SMS webhook: מחובר');
  console.log('  Ctrl+C להפסקה');
  console.log('╚════════════════════════════════════════════════╝\n');
});
