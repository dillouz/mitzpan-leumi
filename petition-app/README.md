# המצפן הלאומי — מיני-סייט עצומה

מיני-סייט לחתימה על ערכי היסוד של המחנה הלאומי-ליברלי (חוקת הליכוד), מבית ח"כ דן אילוז.

## הפעלה מהירה

```bash
cd petition-app
node server.js
```

פתחו בדפדפן: **http://localhost:3000**

אין צורך ב-`npm install` — הקוד לא משתמש בתלויות חיצוניות. דרוש Node.js גרסה 16 ומעלה.

---

## מבנה הפרויקט

```
petition-app/
├── server.js              ← שרת HTTP (Node.js נטו, ללא תלויות)
├── package.json
├── render.yaml            ← קובץ פריסה ל-Render.com
├── data/
│   └── signatures.enc     ← מאגר החתימות — מוצפן AES-256-GCM (נוצר אוטומטית)
└── public/
    ├── index.html         ← דף הנחיתה (כולל CSS + JS inline)
    ├── privacy.html       ← עמוד פרטיות + טופס בקשת הסרה
    ├── hero.jpg           ← תמונת הרקע של ה-Hero
    └── ilouz.jpg          ← תמונת דן אילוז
```

---

## משתני סביבה

| משתנה                  | תיאור                                                                | חובה? | ברירת מחדל    |
|------------------------|-----------------------------------------------------------------------|--------|----------------|
| `PORT`                 | פורט השרת                                                             | לא     | `3000`         |
| `COUNTER_OFFSET`       | תוספת התחלתית למונה החתומים                                          | לא     | `1500`         |
| `ADMIN_USER`           | שם משתמש לדשבורד                                                     | לא     | `admin`        |
| `ADMIN_PASS_HASH`      | סיסמה מוצפנת scrypt — יש לייצר עם `node server.js --hash-password …`  | ✅     | נגזר מ-ADMIN_PASS |
| `ADMIN_PASS`           | סיסמה ב-plaintext (פחות מאובטח; להשתמש רק אם אין ADMIN_PASS_HASH)     | לא     | fallback זמני  |
| `ADMIN_TOTP_SECRET`    | סוד ל-2FA (Google Authenticator). יצירה: `node server.js --generate-totp` | מומלץ | ריק (2FA כבוי) |
| `STRICT_SESSION_IP`    | `true` = הפעלת חיוב IP קבוע לסשן. שימושי בלי רשתות סלולריות/VPN      | לא     | `false`        |
| `DATA_ENCRYPTION_KEY`  | מפתח הצפנה hex (64 תווים). אם לא מוגדר — נוצר חד-פעמי (!)             | ✅     | רנדומלי        |
| `TURNSTILE_SITE_KEY`   | מפתח Turnstile פומבי (לצד הלקוח)                                     | מומלץ | ריק            |
| `TURNSTILE_SECRET_KEY` | מפתח Turnstile סודי (אימות צד-שרת)                                   | מומלץ | ריק            |
| `CRM_WEBHOOK_URL`      | URL שאליו יישלח כל ליד חדש (Make/Zapier/n8n)                         | לא     | ריק            |
| `SMS_WEBHOOK_URL`      | URL לשליחת SMS תודה                                                   | לא     | ריק            |
| `ADMIN_TOKEN`          | legacy — נשמר לתאימות לאחור                                          | לא     | רנדומלי        |

---

## הקשחת כניסת האדמין (חובה לפני פרסום)

### 1. יצירת hash חזק לסיסמה (scrypt)

במקום לשמור את הסיסמה ב-plaintext במשתני הסביבה, ייצרו hash של scrypt:

```bash
node server.js --hash-password "YOUR_STRONG_PASSWORD_HERE"
# Output:
# ADMIN_PASS_HASH=scrypt$16384$8$1$abc123...$def456...
```

העתיקו את הערך ל-Render → Environment → **ADMIN_PASS_HASH**, והסירו את `ADMIN_PASS`.

### 2. הפעלת אימות דו-שלבי (TOTP)

```bash
node server.js --generate-totp
# Output:
# ADMIN_TOTP_SECRET=JBSWY3DPEHPK3PXP...
# otpauth://totp/admin@mitzpan-leumi?secret=...&issuer=...
```

1. הוסיפו את הסוד ל-Render → Environment → **ADMIN_TOTP_SECRET**.
2. סרקו את ה-otpauth URL ב-Google Authenticator / Authy / 1Password (או הדביקו את הסוד ידנית).
3. מעכשיו, כל כניסה לדשבורד דורשת את הקוד המשתנה בן 6 הספרות.

**חשוב**: שמרו גיבוי של הסוד (למשל ב-1Password) — אם תאבדו את המכשיר שלכם, תצטרכו את הסוד כדי להוסיף אותו מחדש.

### 3. חיבור IP קבוע לסשן (אופציונלי)

אם אתם מתחברים מה-IP משרד קבוע, הגדירו `STRICT_SESSION_IP=true`. הסשן ייהרס אוטומטית אם ה-IP משתנה (הגנה נגד session hijacking). לא מומלץ אם אתם מתחברים מסלולר/VPN.

### 4. סוגי אירועים שנרשמים ביומן הביקורת

היומן נגיש ב-`/admin/audit` ונכתב ל-`data/admin-audit.log`:

- `login_success`, `login_failure` (עם הסיבה: bad_username / bad_password / bad_totp)
- `login_rate_limited`
- `logout`
- `session_expired_absolute`, `session_expired_idle`
- `session_ip_mismatch` (אם STRICT_SESSION_IP פעיל)
- `delete_signer` (עם שם ו-id של החתום שנמחק)
- `export_csv`, `export_json`

### ⚠️ חשוב במיוחד — `DATA_ENCRYPTION_KEY`

אם המפתח משתנה או נוצר מחדש, **כל החתימות הקיימות נהפכות לבלתי קריאות**. לפני הפעלה ראשונה בפרודקשן:

```bash
# ליצירת מפתח קבוע:
openssl rand -hex 32
# → הדביקו ב-Render → Environment → DATA_ENCRYPTION_KEY
```

---

## אבטחה והקשחות

### מה מופעל כברירת מחדל ✅

- **הצפנה במנוחה** — AES-256-GCM על קובץ `signatures.enc` (+ אימות שלמות).
- **Session-based admin auth** — עוגיית HttpOnly/SameSite=Strict/Secure; `/admin/login` עם השוואת סיסמה בזמן קבוע (timing-safe). אין טוקן ב-URL.
- **Rate limiting** — 5 חתימות ל-15 דק' לכל IP; 3 ניסיונות התחברות-אדמין בשעה.
- **Input sanitization** — ניקוי תווי בקרה, הגבלת אורך, ולידציית פורמט.
- **XSS protection** — HTML escaping על כל פלט אדמין.
- **CSV injection protection** — escaping של תאים שמתחילים ב-`= + - @ TAB CR`.
- **Security headers** — HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, CSP.
- **HTTPS enforcement** — הפנייה אוטומטית של HTTP ל-HTTPS בפרודקשן.
- **Path traversal protection** — ולידציה שכל קובץ סטטי נמצא בתוך `public/`.
- **Server-side consent enforcement** — אי אפשר להירשם בלי לסמן את ה-checkbox.
- **Right-to-be-forgotten** — עמוד `/privacy.html` עם טופס בקשת הסרה + endpoint ניהולי למחיקה.

### הפעלת Cloudflare Turnstile (אנטי-בוט)

Turnstile היא חלופה של Cloudflare ל-reCAPTCHA. חינם לחלוטין, ללא פאזלים, שומר על פרטיות.

1. היכנסו ל-https://dash.cloudflare.com → **Turnstile** → **Add site**.
2. Domain = הדומיין שלכם (למשל `mitzpanleumi.co.il`).
3. Widget mode = **Managed** (מומלץ).
4. קבלו שני מפתחות:
   - **Site Key** (פומבי) → הגדירו ב-Render כ-`TURNSTILE_SITE_KEY`
   - **Secret Key** → הגדירו ב-Render כ-`TURNSTILE_SECRET_KEY`
5. שמרו → Render יעשה redeploy → הווידג'ט יופיע אוטומטית בטופס החתימה.

אם המפתחות לא מוגדרים, האתר ממשיך לעבוד רגיל ללא אימות אנטי-בוט (מצב דיבוג).

### הפעלת Cloudflare WAF + DDoS protection (חינם)

Render לא כולל WAF מובנה. כדי להוסיף שכבת הגנה נוספת:

1. העבירו את הדומיין ל-Cloudflare (Free plan מספיק).
   - Cloudflare → Add Site → בחרו תוכנית Free.
   - העתיקו את שני ה-Nameservers של Cloudflare אל המרשם (GoDaddy / Gandi / Domain The Net וכו').
2. ב-DNS אצל Cloudflare, הגדירו CNAME של הדומיין → ל-URL של Render, **עם הענן הכתום פעיל** (Proxied).
3. SSL/TLS mode = **Full (strict)**.
4. Security → **Bot Fight Mode** = On.
5. Security → **Under Attack Mode** — כבוי ברירת מחדל; הפעילו ידנית אם מזהים התקפת DDoS.
6. Rules → **WAF** → Managed rules → הפעילו את החבילות: Cloudflare Managed Ruleset, OWASP.
7. Firewall Rules (אופציונלי) — חסמו מדינות ספציפיות אם צריך.

לאחר החיבור, Cloudflare מסנן את הטראפיק *לפני* שהוא מגיע ל-Render — גם DDoS, גם בוטים, גם IPs מוכרים כזדוניים.

---

## API

### ציבורי

| Method | Path                     | תיאור                                                 |
|--------|--------------------------|--------------------------------------------------------|
| POST   | `/api/sign`              | שליחת חתימה חדשה (+ Turnstile אם מופעל)                |
| GET    | `/api/count`             | מחזיר את המונה והיעד הנוכחי                           |
| GET    | `/api/signers`           | 30 חותמים אחרונים (לטיקר החי)                         |
| GET    | `/api/config`            | מחזיר `{ turnstileSiteKey }` לצד הלקוח                |
| POST   | `/api/request-deletion`  | בקשת הסרה מהמאגר (שם/טלפון/אימייל + סיבה)              |

### אדמין (דורש session cookie)

| Method | Path                    | תיאור                                                  |
|--------|-------------------------|---------------------------------------------------------|
| GET    | `/admin/login`          | עמוד התחברות                                           |
| POST   | `/admin/login`          | טיפול בהתחברות (form-encoded)                          |
| GET    | `/admin/logout`         | התנתקות                                                |
| GET    | `/admin`                | דשבורד מלא — טבלת חתימות + סטטיסטיקות + כפתורי ייצוא   |
| POST   | `/admin/delete-signer`  | מחיקת חתימה לפי `id` (כפתור אדום בטבלה)                |
| GET    | `/api/export.csv`       | ייצוא CSV (עברית תקינה באקסל)                          |
| GET    | `/api/export.json`      | ייצוא JSON גולמי                                       |

---

## אינטגרציות

### 1. CRM webhook (Make.com / Zapier / n8n / HubSpot)

1. צרו תרחיש עם trigger מסוג **Webhook** (Instant).
2. העתיקו את ה-URL וקבעו ב-Render כ-`CRM_WEBHOOK_URL`.
3. כל חתימה וכל בקשת הסרה (עם `type: DELETION_REQUEST`) תישלח כ-JSON:

```json
{
  "id": 1713100000000,
  "first_name": "דוד",
  "last_name": "כהן",
  "last_initial": "כ",
  "phone": "0501234567",
  "email": "david@example.com",
  "consent": true,
  "source": "minisite",
  "created_at": "2026-04-14T12:00:00.000Z"
}
```

### 2. SMS תודה

בדיוק אותה שיטה — הגדירו `SMS_WEBHOOK_URL` שיקבל payload:
```json
{ "phone": "0501234567", "text": "תודה שהצטרפת...", "first_name": "דוד" }
```

### 3. שיתוף בוואטסאפ

מוכן ומופעל אוטומטית במסך התודה שקופץ לאחר החתימה.

---

## לוגיקה עסקית

- **מונה החתימות** = מספר החתימות האמיתיות + `COUNTER_OFFSET` (1,500 כברירת מחדל).
- **יעדים**: 10,000 → 25,000 → 50,000 → 100,000 — קידום אוטומטי.
- **מניעת כפילויות**: לפי phone **או** email — מודעה "כבר חתמת".
- **ולידציה**: שם פרטי + שם משפחה + (טלפון או אימייל) + consent=true.

---

## פריסה ל-Render.com

1. חברו את הריפו שלכם ל-Render → New Web Service → Select repo.
2. `render.yaml` יטען אוטומטית את כל הגדרות השירות.
3. עברו ל-Environment ומלאו את המשתנים המסומנים `sync: false`:
   - `ADMIN_PASS`
   - `DATA_ENCRYPTION_KEY` (תוצר של `openssl rand -hex 32`)
   - `TURNSTILE_SITE_KEY` + `TURNSTILE_SECRET_KEY` (מ-Cloudflare)
   - `CRM_WEBHOOK_URL`, `SMS_WEBHOOK_URL`
4. Deploy → ודאו שהשרת עלה → בדקו `/admin/login` עם הסיסמה שהגדרתם.

### דומיין

Render → Settings → Custom Domains → הוסיפו את הדומיין.
אם אתם משתמשים ב-Cloudflare WAF כמתואר למעלה, הגדירו CNAME ב-Cloudflare עם Proxied פעיל.

---

## מדיניות פרטיות

- הנתונים נשמרים **מוצפנים** ב-`data/signatures.enc` בצד השרת.
- אין cookies, אין Google Analytics, אין trackers של צד שלישי.
- Checkbox מפורש לאישור דיוור (כנדרש על פי חוק הספאם הישראלי, תיקון 40).
- בקשת הסרה זמינה ב-`/privacy.html` — מטופלת תוך 7 ימים.

---

## TODO לפני פרסום ציבורי נרחב

- [ ] לוודא שכל משתני הסביבה הסודיים מוגדרים ב-Render (במיוחד `ADMIN_PASS` + `DATA_ENCRYPTION_KEY`).
- [ ] ליצור מפתחות Turnstile ולהפעיל אותם.
- [ ] לחבר דומיין דרך Cloudflare עם Proxied + WAF + Bot Fight Mode.
- [ ] לבדוק חתימה מ-iPhone + Android אמיתיים.
- [ ] לעדכן OG tags עם הדומיין האמיתי.
- [ ] לוודא שה-CRM webhook קולט גם `type: DELETION_REQUEST` ומסמן את הרשומה לטיפול.
