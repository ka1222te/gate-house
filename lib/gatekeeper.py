#!/usr/bin/env python3
"""Gate House: ローカル・ゲートキーパー (127.0.0.1 のみで待受)

cloudflared (Quick Tunnel) -> このプロキシ -> ORIGIN_URL

1. Worker が付与する X-Gate-Secret ヘッダ (起動ごとにランダム) が無いリクエストは 403
   (trycloudflare.com の URL を直接叩かれても通さない)
2. Google アカウント (OAuth 2.0 / OpenID Connect) で認証。
   許可リスト (.env の ALLOWED_EMAILS と ALLOWED_EMAILS_FILE のファイル) に載っているアドレスのみログインを許可
   (ファイルは変更を自動で再読込。削除されたユーザのセッションも即無効)

  gatekeeper.py                サーバ起動 (環境変数 GATE_SECRET 必須)
  gatekeeper.py --check        Google OAuth 設定の確認 (リダイレクト URI を表示)
"""
import base64
import ctypes
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
import re
import secrets
import select
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".state"
SESSIONS_FILE = STATE_DIR / "sessions.json"
CF_STATE_FILE = STATE_DIR / "cloudflare.json"

GATE_HEADER = "X-Gate-Secret"
CLIENT_IP_HEADER = "X-Gate-Client-IP"
AUTH_PREFIX = "/__auth/"
CALLBACK_PATH = "/__auth/callback"

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")

OAUTH_TTL = 600             # Google でのログイン操作の有効期限 (秒)
MAX_PENDING = 5000          # 未完了ログインの上限 (メモリ保護)
MAX_BODY = 20 * 1024 * 1024 # プロキシするリクエストボディ上限
SOCKET_TIMEOUT = 60
MAX_CONNECTIONS = 128      # 同時接続 (スレッド) 上限
MAX_WEBSOCKETS = 64        # 同時 WebSocket 接続の上限 (通常の HTTP 用にスレッドを残す)
WS_IDLE_TIMEOUT = 3600     # WebSocket の無通信タイムアウト (秒)
WS_RECHECK = 60            # WebSocket 接続中にセッション・許可リストを再確認する間隔 (秒)

# レート制限: (回数, 秒)
LIM_START_IP = [(30, 600), (100, 3600)]   # IP 単位のログイン開始
LIM_FAIL_IP = [(20, 3600)]                # IP 単位のログイン失敗

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
       "te", "trailers", "transfer-encoding", "upgrade", "host"}
DROP = {"cdn-loop", GATE_HEADER.lower(), CLIENT_IP_HEADER.lower(), "x-auth-email",
        "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip", "forwarded"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")


def log(s):
    s = re.sub(r"[\x00-\x1f\x7f]", "?", s)   # ログ偽装対策
    sys.stderr.write(time.strftime("%Y-%m-%d %H:%M:%S ") + s + "\n")
    sys.stderr.flush()


# ------------------------------------------------------------------ config
def parse_env(path):
    cfg = {}
    if not path.exists():
        return cfg
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v[:1] in ("'", '"') and v[0] in v[1:]:
            v = v[1:v.index(v[0], 1)]
        else:
            v = v.split(" #")[0].strip()
        cfg[k.strip()] = v
    return cfg


CFG = parse_env(ROOT / ".env")
CFG.setdefault("GATE_PORT", "18787")
CFG.setdefault("SESSION_HOURS", "24")
CFG.setdefault("APP_NAME", "Web アプリ")
ORIGIN = urllib.parse.urlsplit(CFG.get("ORIGIN_URL", "").rstrip("/"))
ORIGIN_BASE = f"{ORIGIN.scheme}://{ORIGIN.netloc}"
SESSION_TTL = int(float(CFG["SESSION_HOURS"]) * 3600)
APP_NAME = CFG["APP_NAME"]

# Cookie 名: __Host-<COOKIE_NAME>_session / __Host-<COOKIE_NAME>_oauth
#   (__Host- 接頭辞は Secure・Path=/・Domain 無しを強制するため固定)
CFG.setdefault("COOKIE_NAME", "gate-house")
if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", CFG["COOKIE_NAME"]):
    sys.exit(f"[x] .env の COOKIE_NAME が不正です (英数字・_・- で 32 文字以内): {CFG['COOKIE_NAME']!r}")
COOKIE_PREFIX = f"__Host-{CFG['COOKIE_NAME']}_"
SESSION_COOKIE = COOKIE_PREFIX + "session"
OAUTH_COOKIE = COOKIE_PREFIX + "oauth"


def public_url():
    """利用者がアクセスする公開 URL (PUBLIC_URL > scripts/setup.sh で登録した workers.dev ホスト)"""
    if CFG.get("PUBLIC_URL"):
        return CFG["PUBLIC_URL"].rstrip("/")
    try:
        return "https://" + json.loads(CF_STATE_FILE.read_text())["host"]
    except (FileNotFoundError, ValueError, KeyError):
        return ""


REDIRECT_URI = ""  # main() で決定
PUBLIC_ORIGIN = ""  # main() で決定 (WebSocket の Origin 検証用)

# 許可リスト: ALLOWED_EMAILS (カンマ/空白区切り) + ALLOWED_EMAILS_FILE (相対パスはこのディレクトリ基準)
EMAILS_FILE = ROOT / (CFG.get("ALLOWED_EMAILS_FILE") or "allowed_emails.txt")


# ------------------------------------------------------------------ allowlist
def parse_allow_entries(items, source):
    """アドレス / @ドメイン の並びを (emails, domains) に分ける"""
    emails, domains = set(), set()
    for s in items:
        s = s.strip().lower()
        if s.startswith("@") and EMAIL_RE.match("x" + s):
            domains.add(s[1:])
        elif EMAIL_RE.match(s):
            emails.add(s)
        elif s:
            log(f"allowlist: ignored invalid entry {s!r} ({source})")
    return emails, domains


class Allowlist:
    def __init__(self, path, inline=""):
        self.path, self.mtime, self.emails, self.domains = path, None, set(), set()
        self.lock = threading.Lock()
        # .env の値は起動時に固定 (変更は再起動で反映)
        self.env_emails, self.env_domains = parse_allow_entries(re.split(r"[\s,]+", inline), ".env ALLOWED_EMAILS")

    def _fallback(self, state, msg):
        """ファイルが無い/読めないときは、ファイル分は何も許可しない (.env の ALLOWED_EMAILS のみ有効)"""
        if self.mtime != state:   # 状態が変わったときだけログ
            log(f"allowlist: {msg}; using .env ALLOWED_EMAILS only "
                f"({len(self.env_emails)} emails, {len(self.env_domains)} domains)")
        self.emails, self.domains, self.mtime = set(), set(), state

    def _reload(self):
        try:
            m = self.path.stat().st_mtime_ns
        except FileNotFoundError:
            return self._fallback("missing", f"{self.path} not found")
        except OSError as e:
            return self._fallback("error", f"cannot access {self.path}: {e.strerror}")
        if m == self.mtime:
            return
        try:
            text = self.path.read_text()
        except FileNotFoundError:   # stat 後に削除された
            return self._fallback("missing", f"{self.path} not found")
        except (OSError, UnicodeDecodeError) as e:
            return self._fallback("error", f"cannot read {self.path}: {type(e).__name__}")
        lines = (line.split("#", 1)[0] for line in text.splitlines())
        self.emails, self.domains = parse_allow_entries(lines, self.path.name)
        self.mtime = m
        log(f"allowlist loaded: {self.path.name}: {len(self.emails)} emails, {len(self.domains)} domains"
            f" / .env: {len(self.env_emails)} emails, {len(self.env_domains)} domains")

    def allowed(self, email):
        with self.lock:
            self._reload()
            email = email.lower()
            domain = email.rsplit("@", 1)[-1]
            return (email in self.emails or email in self.env_emails
                    or domain in self.domains or domain in self.env_domains)

    def empty(self):
        with self.lock:
            self._reload()
            return not (self.emails or self.domains or self.env_emails or self.env_domains)


ALLOW = Allowlist(EMAILS_FILE, CFG.get("ALLOWED_EMAILS", ""))


# ------------------------------------------------------------------ sessions (サーバ側管理)
class Sessions:
    """Cookie にはランダム ID のみ。サーバ側は SHA-256(ID) をキーに保存 (ファイル漏洩でも Cookie を復元不可)"""

    def __init__(self, path):
        self.path, self.lock, self.data = path, threading.Lock(), {}
        try:
            self.data = json.loads(path.read_text())
        except (FileNotFoundError, ValueError):
            self.data = {}
        self._gc()

    @staticmethod
    def _h(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def _gc(self):
        now = time.time()
        for k in [k for k, v in self.data.items() if v["x"] < now]:
            del self.data[k]

    def _save(self):
        STATE_DIR.mkdir(mode=0o700, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)

    def create(self, email):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self._gc()
            self.data[self._h(token)] = {"e": email, "x": int(time.time()) + SESSION_TTL}
            self._save()
        return token

    def check(self, token):
        if not token or len(token) > 100:
            return None
        with self.lock:
            s = self.data.get(self._h(token))
        if not s or s["x"] < time.time() or not ALLOW.allowed(s["e"]):
            return None
        return s["e"]

    def revoke(self, token):
        with self.lock:
            if self.data.pop(self._h(token or ""), None):
                self._save()


SESSIONS = None  # main() で初期化


# ------------------------------------------------------------------ rate limit
class Limiter:
    def __init__(self):
        self.ev = defaultdict(deque)
        self.lock = threading.Lock()
        self.last_gc = time.time()

    def _gc(self, now):
        if now - self.last_gc < 600:
            return
        self.last_gc = now
        for k in [k for k, q in self.ev.items() if not q or q[-1] < now - 86400]:
            del self.ev[k]

    def check(self, key, rules, record=True):
        """全ルールを満たせば True (record=True なら記録)"""
        now = time.time()
        with self.lock:
            self._gc(now)
            q = self.ev[key]
            longest = max(w for _, w in rules)
            while q and q[0] < now - longest:
                q.popleft()
            for limit, window in rules:
                if sum(1 for t in q if t >= now - window) >= limit:
                    return False
            if record:
                q.append(now)
            return True

    def add(self, key):
        with self.lock:
            self.ev[key].append(time.time())


LIMIT = Limiter()
PENDING = {}          # sha256(state) -> {nonce, verifier, exp, next, bind}
PENDING_LOCK = threading.Lock()


# ------------------------------------------------------------------ Google OAuth / OpenID Connect
def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def google_auth_url(state, nonce, verifier):
    q = {
        "client_id": CFG["GOOGLE_CLIENT_ID"],
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "nonce": nonce,
        "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    if CFG.get("GOOGLE_HD"):
        q["hd"] = CFG["GOOGLE_HD"]   # アカウント選択画面のヒント (検証は id_token の hd で行う)
    return GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(q)


def google_exchange(code, verifier, nonce):
    """認可コードを id_token に交換し、検証済みのメールアドレスを返す。失敗時は ValueError。

    id_token は TLS で Google のトークンエンドポイントから直接受け取るため、
    OpenID Connect Core 3.1.3.7 に従い署名検証の代わりに TLS のサーバ証明書検証で真正性を担保する。"""
    body = urllib.parse.urlencode({
        "code": code,
        "client_id": CFG["GOOGLE_CLIENT_ID"],
        "client_secret": CFG["GOOGLE_CLIENT_SECRET"],
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(GOOGLE_TOKEN_URL, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as res:
            tok = json.loads(res.read(65536))
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read(4096)).get("error", "")
        except ValueError:
            err = ""
        raise ValueError(f"token endpoint HTTP {e.code} {err}") from None
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        raise ValueError(f"token endpoint error: {type(e).__name__}") from None

    try:
        claims = json.loads(b64url_decode(tok["id_token"].split(".")[1]))
    except (KeyError, IndexError, ValueError, TypeError):
        raise ValueError("invalid id_token") from None
    now = time.time()
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise ValueError("bad iss")
    aud = claims.get("aud")
    if aud != CFG["GOOGLE_CLIENT_ID"] and not (isinstance(aud, list) and CFG["GOOGLE_CLIENT_ID"] in aud):
        raise ValueError("bad aud")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - 60:
        raise ValueError("expired id_token")
    if not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
        raise ValueError("bad nonce")
    email = str(claims.get("email", "")).lower()
    if claims.get("email_verified") is not True or not EMAIL_RE.match(email):
        raise ValueError("email not verified")
    if CFG.get("GOOGLE_HD") and claims.get("hd") != CFG["GOOGLE_HD"]:
        raise ValueError(f"hd mismatch ({email})")
    return email


# ------------------------------------------------------------------ HTML
CSS = ("body{font-family:system-ui,sans-serif;max-width:24rem;margin:4rem auto;padding:0 1rem;color:#222}"
       "h1{font-size:1.3rem}"
       "button,.btn{display:block;width:100%;box-sizing:border-box;text-align:center;text-decoration:none;"
       "font-size:1rem;padding:.7rem;background:#2563eb;color:#fff;border:0;border-radius:6px;cursor:pointer}"
       ".msg{padding:.6rem;border-radius:6px;background:#fef3c7}.err{background:#fee2e2}a{color:#2563eb}"
       "@media(prefers-color-scheme:dark){body{background:#111;color:#eee}.msg{background:#443}.err{background:#511}}")


def render(title, inner):
    t = html.escape(title)
    return (f'<!doctype html><html lang="ja"><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{t}</title><style>{CSS}</style><body><h1>{t}</h1>{inner}</body></html>')


def page_login(next_, msg=""):
    m = f'<p class="msg err">{html.escape(msg)}</p>' if msg else ""
    href = "/__auth/google?next=" + urllib.parse.quote(next_, safe="")
    return render(f"{APP_NAME} ログイン", f"""{m}
<p>許可された Google アカウントでログインしてください。</p>
<p><a class="btn" href="{html.escape(href)}">Google アカウントでログイン</a></p>""")


def page_logout():
    return render("ログアウト", """<form method="post" action="/__auth/logout">
<button>ログアウトする</button></form>""")


SAFE_NEXT = re.compile(r"^/(?![/\\])[\x21-\x7e]*$")   # 相対パスのみ。空白/制御文字/非ASCII/バックスラッシュ始まり不可


def safe_next(n):
    return n if len(n) <= 2000 and SAFE_NEXT.match(n) and "\\" not in n else "/"


def private_cache(v):
    """共有キャッシュ (Cloudflare 等) に保存させない"""
    parts = [p.strip() for p in (v or "").split(",") if p.strip()]
    low = [p.lower() for p in parts]
    if any(p in ("no-store", "private") for p in low):
        return ", ".join(parts)
    parts = [p for p in parts if p.lower() != "public" and not p.lower().startswith("s-maxage")]
    return ", ".join(["private", *parts])


# ------------------------------------------------------------------ handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gate-house"
    sys_version = ""
    timeout = SOCKET_TIMEOUT
    SECRET = b""

    def log_message(self, fmt, *args):
        log(f"{self.client_ip()} {fmt % args}")

    def client_ip(self):
        h = getattr(self, "headers", None)
        ip = (h.get(CLIENT_IP_HEADER) if h else "") or "-"
        return re.sub(r"[^0-9A-Fa-f:.]", "", ip)[:45] or "-"

    def rate_key(self):
        """レート制限のキー。IPv6 は 1 人が /64 単位で大量のアドレスを持てるため /64 にまとめる"""
        ip = self.client_ip()
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return ip
        if a.version == 6 and a.ipv4_mapped is None:
            return str(ipaddress.ip_network(f"{ip}/64", strict=False))
        return ip

    # ---------- helpers
    def cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                out.setdefault(k, v)
        return out

    def send(self, code, body, ctype="text/html; charset=utf-8", headers=()):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                             "frame-ancestors 'none'; base-uri 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, loc, headers=()):
        self.send(303, "", "text/plain", [("Location", loc), ("Referrer-Policy", "no-referrer"), *headers])

    def _read_body(self, limit):
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            chunks, total = [], 0
            while True:
                # 負の値 ("-1") や "0x10" を受け付けると read(-1) で上限なしに読み込むため 16 進数字のみ許可
                tok = self.rfile.readline(100).split(b";")[0].strip()
                if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", tok):
                    raise ValueError("bad chunk size")
                size = int(tok, 16)
                if size == 0:
                    for _ in range(64):   # トレーラ行を無限に送られてスレッドを占有されないよう上限
                        if self.rfile.readline(8192) in (b"\r\n", b"\n", b""):
                            break
                    else:
                        raise ValueError("too many trailers")
                    break
                total += size
                if total > limit:
                    raise ValueError("body too large")
                chunks.append(self.rfile.read(size))
                self.rfile.readline(100)
            return b"".join(chunks)
        cl = (self.headers.get("Content-Length") or "0").strip()
        if not re.fullmatch(r"[0-9]{1,12}", cl):   # int() が通す "+5" "1_0" 等は不可
            raise ValueError("bad content-length")
        n = int(cl)
        if n > limit:
            raise ValueError("body too large")
        return self.rfile.read(n) if n else None

    def has_body(self):
        return self.headers.get("Content-Length", "0").strip() != "0" or bool(self.headers.get("Transfer-Encoding"))

    def set_cookie(self, name, value, max_age):
        return ("Set-Cookie", f"{name}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Lax")

    # ---------- entry
    def handle_any(self):
        got = (self.headers.get(GATE_HEADER) or "").encode()
        if not hmac.compare_digest(got, self.SECRET):
            self.close_connection = True
            return self.send(403, "Forbidden", "text/plain")
        if not self.path.startswith("/") or re.search(r"[\x00-\x20\x7f-\xff]", self.path):
            self.close_connection = True
            return self.send(400, "Bad Request", "text/plain")

        path = urllib.parse.urlsplit(self.path).path
        try:
            if path.startswith(AUTH_PREFIX):
                # 認証用 URL はボディを使わない。読み残したボディが同じ接続の次のリクエストとして
                # 解釈される (cloudflared は接続を他の利用者と共用する) のを防ぐため、読まずに切断
                # (ログアウトの POST もボディ不要。ゆっくり送るボディでスレッドを占有されることも防ぐ)
                if self.has_body():
                    self.close_connection = True
                return self.auth_route(path)
            email = SESSIONS.check(self.cookies().get(SESSION_COOKIE, ""))
            if not email:
                if self.has_body():
                    self.close_connection = True   # 未認証のボディは読まずに切断
                if self.command == "GET" and "text/html" in self.headers.get("Accept", ""):
                    return self.redirect("/__auth/login?next=" + urllib.parse.quote(self.path, safe=""))
                return self.send(401, '{"detail":"login required"}', "application/json")
            return self.proxy(email)
        except ValueError:
            self.close_connection = True
            return self.send(413, "Payload Too Large", "text/plain")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = handle_any

    # ---------- auth
    def auth_route(self, path):
        ip = self.client_ip()
        rk = self.rate_key()
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))

        if path == "/__auth/login" and self.command in ("GET", "HEAD"):
            return self.send(200, page_login(safe_next(q.get("next", "/"))))

        # Google へリダイレクト (state / nonce / PKCE を発行)
        if path == "/__auth/google" and self.command in ("GET", "HEAD"):
            next_ = safe_next(q.get("next", "/"))
            if not LIMIT.check(f"start-ip:{rk}", LIM_START_IP):
                return self.send(429, page_login(next_, "ログイン試行が多すぎます。しばらく待ってから再度お試しください。"))
            state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
            bind = secrets.token_urlsafe(32)   # state をこのブラウザに結び付ける (ログイン CSRF 対策)
            with PENDING_LOCK:
                now = time.time()
                for k in [k for k, v in PENDING.items() if v["exp"] < now]:
                    del PENDING[k]
                if len(PENDING) >= MAX_PENDING:
                    return self.send(503, page_login(next_, "混雑しています。しばらくしてから再度お試しください。"))
                PENDING[hashlib.sha256(state.encode()).hexdigest()] = {
                    "nonce": nonce, "verifier": verifier, "exp": now + OAUTH_TTL,
                    "next": next_, "bind": hashlib.sha256(bind.encode()).hexdigest()}
            return self.redirect(google_auth_url(state, nonce, verifier),
                                 [self.set_cookie(OAUTH_COOKIE, bind, OAUTH_TTL)])

        # Google からの戻り
        if path == CALLBACK_PATH and self.command in ("GET", "HEAD"):
            clear = [self.set_cookie(OAUTH_COOKIE, "", 0)]
            if not LIMIT.check(f"fail-ip:{rk}", LIM_FAIL_IP, record=False):
                return self.send(429, page_login("/", "ログイン失敗が多すぎます。しばらく待ってから再度お試しください。"), headers=clear)
            state = q.get("state", "")[:100]
            with PENDING_LOCK:
                p = PENDING.pop(hashlib.sha256(state.encode()).hexdigest(), None)
            bind = self.cookies().get(OAUTH_COOKIE, "")[:100]
            if not p or p["exp"] < time.time() or \
               not hmac.compare_digest(p["bind"], hashlib.sha256(bind.encode()).hexdigest()):
                LIMIT.add(f"fail-ip:{rk}")
                return self.send(400, page_login("/", "ログインの有効期限が切れました。もう一度お試しください。"), headers=clear)
            if q.get("error") or not q.get("code"):
                log(f"oauth canceled/error {q.get('error', '')[:50]!r} (ip {ip})")
                return self.send(400, page_login(p["next"], "Google でのログインがキャンセルされました。"), headers=clear)
            try:
                email = google_exchange(q["code"][:2048], p["verifier"], p["nonce"])
            except ValueError as e:
                LIMIT.add(f"fail-ip:{rk}")
                log(f"oauth FAILED: {e} (ip {ip})")
                return self.send(400, page_login(p["next"], "ログインに失敗しました。もう一度お試しください。"), headers=clear)
            if not ALLOW.allowed(email):
                LIMIT.add(f"fail-ip:{rk}")
                log(f"login DENIED {email} (not in allowlist, ip {ip})")
                return self.send(403, page_login(p["next"],
                                 f"{email} はアクセスを許可されていません。別のアカウントでお試しください。"), headers=clear)
            log(f"login OK {email} (ip {ip})")
            # セッション固定化対策: 既存セッションは破棄して新規発行
            SESSIONS.revoke(self.cookies().get(SESSION_COOKIE))
            token = SESSIONS.create(email)
            return self.redirect(p["next"], [self.set_cookie(SESSION_COOKIE, token, SESSION_TTL), *clear])

        if path == "/__auth/logout":
            if self.command == "POST":   # GET でのログアウトは CSRF で強制ログアウトされうるため確認画面
                SESSIONS.revoke(self.cookies().get(SESSION_COOKIE))
                return self.redirect("/__auth/login", [self.set_cookie(SESSION_COOKIE, "", 0)])
            return self.send(200, page_logout())

        return self.send(404, "Not Found", "text/plain")

    # ---------- proxy
    def forward_headers(self, email):
        """中継先へ送るヘッダ (hop-by-hop・認証用ヘッダ・ゲートの Cookie を除く)"""
        fwd = {}
        for k, v in self.headers.items():
            # "X-Auth_Email" のような _ 入りの名前は、WSGI/CGI 系のサーバで "X-Auth-Email" と
            # 同一視されることがあるため、- に揃えてから判定する (X-Auth-Email 等の偽装対策)
            lk = k.lower().replace("_", "-")
            if lk in HOP or lk in DROP or lk.startswith("cf-") or lk == "cookie":
                continue
            fwd[k] = v
        cookies = [f"{k}={v}" for k, v in self.cookies().items() if not k.startswith(COOKIE_PREFIX)]
        if cookies:
            fwd["Cookie"] = "; ".join(cookies)
        fwd["Host"] = ORIGIN.netloc
        fwd["X-Auth-Email"] = email
        fwd["X-Forwarded-For"] = self.client_ip()
        # 利用者が送った X-Forwarded-Host 等は使わず公開 URL から設定 (内部アプリが URL 生成に使うため)
        fwd["X-Forwarded-Host"] = urllib.parse.urlsplit(PUBLIC_ORIGIN).netloc
        fwd["X-Forwarded-Proto"] = "https"
        return fwd

    def proxy(self, email):
        upgrade = (self.headers.get("Upgrade") or "").lower()
        if upgrade == "websocket":
            return self.websocket(email)
        if upgrade:
            return self.send(501, "Protocol upgrade is not supported", "text/plain")
        body = self._read_body(MAX_BODY)
        fwd = self.forward_headers(email)
        if body is not None:
            fwd["Content-Length"] = str(len(body))

        Conn = http.client.HTTPSConnection if ORIGIN.scheme == "https" else http.client.HTTPConnection
        conn = Conn(ORIGIN.netloc, timeout=120)
        try:
            conn.request(self.command, self.path, body=body, headers=fwd)
            res = conn.getresponse()
        except Exception as e:  # noqa: BLE001
            conn.close()
            log(f"origin error: {e!r}")
            return self.send(502, "Bad Gateway", "text/plain")

        try:
            self.send_response(res.status, res.reason)
            has_len = has_cc = False
            for k, v in res.getheaders():
                lk = k.lower()
                if lk in HOP:
                    continue
                if lk == "content-length":
                    has_len = True
                if lk == "cache-control":
                    has_cc, v = True, private_cache(v)
                if lk == "set-cookie" and v.split("=", 1)[0].strip().startswith(COOKIE_PREFIX):
                    continue   # 内部アプリがゲートのセッション Cookie を上書き (セッション固定) できないように
                if lk == "location" and (v == ORIGIN_BASE or
                                         (v.startswith(ORIGIN_BASE) and v[len(ORIGIN_BASE)] in "/?#")):
                    v = v[len(ORIGIN_BASE):] or "/"   # "http://app.example.evil" のような別ホストは書き換えない
                self.send_header(k, v)
            if not has_cc:
                self.send_header("Cache-Control", "private")
            no_body = self.command == "HEAD" or res.status in (204, 304) or 100 <= res.status < 200
            chunked = not has_len and not no_body
            if chunked:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if no_body:
                return
            while True:
                data = res.read1(65536)
                if not data:
                    break
                self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data) if chunked else data)
                self.wfile.flush()
            if chunked:
                self.wfile.write(b"0\r\n\r\n")
        finally:
            conn.close()


    # ---------- WebSocket
    WS_SEM = threading.BoundedSemaphore(MAX_WEBSOCKETS)

    def websocket(self, email):
        """WebSocket のハンドシェイクを中継し、以後は双方向にバイト列をそのまま転送する"""
        self.close_connection = True
        if self.command != "GET" or self.has_body():
            return self.send(400, "Bad Request", "text/plain")
        # Cross-Site WebSocket Hijacking 対策: ブラウザが付ける Origin は公開 URL のみ許可
        origin_hdr = self.headers.get("Origin")
        if origin_hdr is not None and origin_hdr.rstrip("/") != PUBLIC_ORIGIN:
            log(f"websocket REJECTED bad origin {origin_hdr[:100]!r} ({email})")
            return self.send(403, "Forbidden origin", "text/plain")
        if not self.WS_SEM.acquire(blocking=False):
            log("websocket limit reached")
            return self.send(503, "Too many WebSocket connections", "text/plain")
        upstream = None
        try:
            fwd = self.forward_headers(email)
            fwd["Connection"] = "Upgrade"
            fwd["Upgrade"] = "websocket"
            if origin_hdr is not None:   # 中継先の同一オリジン検査を通すため (公開 URL であることは検証済み)
                fwd["Origin"] = ORIGIN_BASE
            port = ORIGIN.port or (443 if ORIGIN.scheme == "https" else 80)
            try:
                upstream = socket.create_connection((ORIGIN.hostname, port), timeout=30)
                if ORIGIN.scheme == "https":
                    upstream = ssl.create_default_context().wrap_socket(upstream, server_hostname=ORIGIN.hostname)
                head = f"GET {self.path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in fwd.items()) + "\r\n"
                upstream.sendall(head.encode("latin-1", "replace"))
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = upstream.recv(65536)
                    if not chunk or len(buf) > 65536:
                        raise ConnectionError("bad handshake response")
                    buf += chunk
            except (OSError, ConnectionError) as e:
                log(f"origin websocket error: {e!r}")
                return self.send(502, "Bad Gateway", "text/plain")
            head, rest = buf.split(b"\r\n\r\n", 1)
            status = head.split(b"\r\n", 1)[0].split(b" ")
            code = int(status[1]) if len(status) > 1 and status[1].isdigit() else 502
            self.log_request(code)
            if code != 101:
                return self._ws_relay_refusal(upstream, head, rest)
            self.wfile.flush()
            self.connection.sendall(head + b"\r\n\r\n" + rest)
            log(f"websocket open {self.path[:200]} ({email})")
            reason = self._ws_pipe(upstream)
            log(f"websocket closed {self.path[:200]} ({email}): {reason}")
        finally:
            if upstream is not None:
                try:
                    upstream.close()
                except OSError:
                    pass
            self.WS_SEM.release()

    def _ws_relay_refusal(self, upstream, head, rest):
        """中継先がアップグレードを拒否した応答 (401/403 など) をそのまま返して切断"""
        lines = [l for l in head.split(b"\r\n")
                 if l.split(b":", 1)[0].strip().lower() not in (b"connection", b"keep-alive", b"upgrade")]
        clen = next((int(l.split(b":", 1)[1].strip()) for l in lines[1:]
                     if l.split(b":", 1)[0].strip().lower() == b"content-length"
                     and l.split(b":", 1)[1].strip().isdigit()), None)
        self.connection.sendall(b"\r\n".join(lines) + b"\r\nConnection: close\r\n\r\n" + rest)
        sent, end = len(rest), time.time() + SOCKET_TIMEOUT
        upstream.settimeout(SOCKET_TIMEOUT)
        while (clen is None or sent < clen) and time.time() < end:
            try:
                data = upstream.recv(65536)
            except OSError:
                break
            if not data:
                break
            self.connection.sendall(data)
            sent += len(data)

    def _ws_pipe(self, upstream):
        client = self.connection
        token = self.cookies().get(SESSION_COOKIE, "")
        # ハンドシェイク後にクライアントが送ってきてバッファに残っている分を先に流す
        client.setblocking(False)
        try:
            pending = self.rfile.read1(65536) or b""
        except BlockingIOError:
            pending = b""
        finally:
            client.setblocking(True)
        if pending:
            upstream.sendall(pending)
        client.settimeout(SOCKET_TIMEOUT)
        upstream.settimeout(SOCKET_TIMEOUT)
        peer = {client: upstream, upstream: client}
        last_io = last_check = time.time()
        while True:
            if isinstance(upstream, ssl.SSLSocket) and upstream.pending():
                ready = [upstream]
            else:
                ready, _, _ = select.select([client, upstream], [], [], 10)
            now = time.time()
            for sock in ready:
                try:
                    data = sock.recv(65536)
                except (ssl.SSLWantReadError, BlockingIOError):
                    continue
                except OSError as e:
                    return f"{'client' if sock is client else 'origin'} error {type(e).__name__}"
                if not data:
                    return f"{'client' if sock is client else 'origin'} closed"
                try:
                    peer[sock].sendall(data)
                except OSError as e:
                    return f"{'origin' if sock is client else 'client'} error {type(e).__name__}"
                last_io = now
            if now - last_io > WS_IDLE_TIMEOUT:
                return "idle timeout"
            if now - last_check > WS_RECHECK:   # ログアウト・許可リストからの削除を接続中にも反映
                last_check = now
                if not SESSIONS.check(token):
                    return "session revoked"


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    sem = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, client_address):
        if not self.sem.acquire(timeout=5):
            log("connection limit reached; dropping")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.sem.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.sem.release()

    def handle_error(self, request, client_address):
        e = sys.exc_info()[1]
        if isinstance(e, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            return
        log(f"handler error: {type(e).__name__}: {e}")


def _die_with_parent():
    """子プロセス (cloudflared) を、gatekeeper が終了/クラッシュしたら即 SIGKILL させる。
    gatekeeper が落ちた後に第三者が 127.0.0.1:GATE_PORT を奪っても、トンネル経由の通信
    (秘密ヘッダ・Cookie) がそこへ流れないようにするため。"""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    PR_SET_PDEATHSIG = 1
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() == 1:   # 既に親が死んでいた
        os._exit(1)


def spawn_tunnel(port):
    exe = os.environ.get("CLOUDFLARED")
    if not exe:
        return None
    env = {k: v for k, v in os.environ.items() if k not in ("GATE_SECRET",)}
    logf = open(STATE_DIR / "cloudflared.log", "ab", buffering=0)
    p = subprocess.Popen(
        [exe, "tunnel", "--no-autoupdate", "--management-diagnostics=false",
         "--metrics", "127.0.0.1:0", "--url", f"http://127.0.0.1:{port}"],
        stdin=subprocess.DEVNULL, stdout=logf, stderr=logf, env=env,
        preexec_fn=_die_with_parent, close_fds=True)
    (STATE_DIR / "cloudflared.pid").write_text(str(p.pid))
    log(f"cloudflared started (pid {p.pid})")

    def watch():
        rc = p.wait()
        log(f"cloudflared exited (rc={rc}); stopping gatekeeper")
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=watch, daemon=True).start()
    return p


def check_config():
    """設定に問題があればメッセージを返す"""
    global REDIRECT_URI, PUBLIC_ORIGIN
    errs = []
    for k in ("ORIGIN_URL", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
        if not CFG.get(k):
            errs.append(f".env の {k} が未設定です")
    if CFG.get("ORIGIN_URL") and ORIGIN.scheme not in ("http", "https"):
        errs.append(f"ORIGIN_URL が不正です: {CFG['ORIGIN_URL']!r}")
    base = public_url()
    if not base:
        errs.append("公開 URL が不明です (先に ./scripts/setup.sh を実行するか、.env に PUBLIC_URL を設定)")
    elif not base.startswith("https://"):
        errs.append(f"PUBLIC_URL は https:// で始めてください: {base!r}")
    REDIRECT_URI = base + CALLBACK_PATH if base else ""
    u = urllib.parse.urlsplit(base)
    PUBLIC_ORIGIN = f"{u.scheme}://{u.netloc}" if base else ""
    if ALLOW.empty():
        errs.append(f"許可リストが空です (.env の ALLOWED_EMAILS か {EMAILS_FILE.name} に記入)")
    return errs


def main():
    global SESSIONS
    errs = check_config()
    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        for e in errs:
            print(f"[!] {e}")
        if REDIRECT_URI:
            print(f"[+] Google の「承認済みのリダイレクト URI」に登録する値: {REDIRECT_URI}")
        sys.exit(1 if errs else 0)
    if errs:
        sys.exit("[x] " + "\n[x] ".join(errs))
    secret = os.environ.get("GATE_SECRET", "")
    if len(secret) < 32:
        sys.exit("[x] GATE_SECRET が未設定または短すぎます")
    Handler.SECRET = secret.encode()
    os.umask(0o077)
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    SESSIONS = Sessions(SESSIONS_FILE)
    port = int(CFG["GATE_PORT"])
    srv = Server(("127.0.0.1", port), Handler)   # ポート使用中なら例外で終了 (乗っ取り検知)
    log(f"gatekeeper listening on 127.0.0.1:{port} -> {ORIGIN_BASE} (redirect_uri {REDIRECT_URI})")
    tunnel = spawn_tunnel(port)

    def term(*_):
        if tunnel and tunnel.poll() is None:
            tunnel.kill()
        os._exit(0)
    signal.signal(signal.SIGTERM, term)
    signal.signal(signal.SIGINT, term)
    srv.serve_forever()


if __name__ == "__main__":
    main()
