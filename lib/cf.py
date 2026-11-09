#!/usr/bin/env python3
"""Gate House: Cloudflare API ヘルパ (標準ライブラリのみ)

  cf.py setup              Worker を作成・更新 (冪等)
  cf.py set-tunnel URL     Worker のトンネル先を更新 (GATE_SECRET は環境変数)
  cf.py clear-tunnel       Worker をメンテナンス表示に切替
  cf.py wait-ready URL     トンネルが疎通するまで待機
  cf.py status             現在の設定を表示
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = ROOT / ".state"
STATE_FILE = STATE_DIR / "cloudflare.json"
API = "https://api.cloudflare.com/client/v4"


# ---------------------------------------------------------------- config
def load_config():
    path = ROOT / ".env"
    if not path.exists():
        sys.exit(f"[x] {path} がありません。.env.example をコピーして編集してください。")
    cfg = {}
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
    for k in ("CF_API_TOKEN", "CF_ACCOUNT_ID", "WORKER_NAME"):
        if not cfg.get(k):
            sys.exit(f"[x] .env の {k} が未設定です。")
    return cfg


def load_state():
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}


def save_state(st):
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    STATE_FILE.write_text(json.dumps(st, indent=2, ensure_ascii=False))
    os.chmod(STATE_FILE, 0o600)


# ---------------------------------------------------------------- HTTP
class CF:
    def __init__(self, cfg):
        self.token = cfg["CF_API_TOKEN"]
        self.acc = cfg["CF_ACCOUNT_ID"]

    def req(self, method, path, body=None, raw=None, ctype=None, ok404=False):
        url = f"{API}/accounts/{self.acc}{path}"
        headers = {"Authorization": f"Bearer {self.token}"}
        data = None
        if raw is not None:
            data, headers["Content-Type"] = raw, ctype
        elif body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        r = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(r, timeout=60) as res:
                j = json.loads(res.read() or b"{}")
        except urllib.error.HTTPError as e:
            if ok404 and e.code == 404:
                return None
            txt = e.read().decode(errors="replace")
            try:
                errs = json.loads(txt).get("errors", txt)
            except ValueError:
                errs = txt
            raise SystemExit(f"[x] API {method} {path} -> HTTP {e.code}: {errs}")
        if not j.get("success", True):
            raise SystemExit(f"[x] API {method} {path} failed: {j.get('errors')}")
        return j.get("result")

    def list_all(self, path):
        out, page = [], 1
        while True:
            sep = "&" if "?" in path else "?"
            res = self.req("GET", f"{path}{sep}page={page}&per_page=50") or []
            out += res
            if len(res) < 50:
                return out
            page += 1


# ---------------------------------------------------------------- commands
def cmd_setup(cfg):
    cf, st = CF(cfg), load_state()
    name = cfg["WORKER_NAME"]

    # 1) workers.dev サブドメイン
    sub = (cf.req("GET", "/workers/subdomain", ok404=True) or {}).get("subdomain")
    if not sub:
        sys.exit("[x] workers.dev サブドメインが未登録です。ダッシュボードの Workers & Pages で登録してください。")
    host = f"{name}.{sub}.workers.dev"
    print(f"[+] Worker ホスト: {host}")

    # 2) Worker アップロード (secret は保持)
    code = (ROOT / "worker" / "worker.js").read_bytes()
    meta = {
        "main_module": "worker.js",
        "compatibility_date": "2025-01-01",
        "bindings": [],
        "keep_bindings": ["secret_text"],
    }
    b = f"----gate-house{uuid.uuid4().hex}"
    parts = [
        f'--{b}\r\nContent-Disposition: form-data; name="metadata"; filename="metadata.json"\r\n'
        f"Content-Type: application/json\r\n\r\n".encode() + json.dumps(meta).encode() + b"\r\n",
        f'--{b}\r\nContent-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
        f"Content-Type: application/javascript+module\r\n\r\n".encode() + code + b"\r\n",
        f"--{b}--\r\n".encode(),
    ]
    cf.req("PUT", f"/workers/scripts/{name}", raw=b"".join(parts),
           ctype=f"multipart/form-data; boundary={b}")
    print(f"[+] Worker デプロイ: {name}")

    # 3) workers.dev 有効化 / プレビューURL 無効化
    cf.req("POST", f"/workers/scripts/{name}/subdomain",
           {"enabled": True, "previews_enabled": False})
    print("[+] workers.dev ルート有効 / Preview URL 無効")

    # 4) 初期状態はメンテナンス表示
    secrets = cf.req("GET", f"/workers/scripts/{name}/secrets") or []
    if not any(s.get("name") == "TUNNEL_CONFIG" for s in secrets):
        put_tunnel(cf, cfg, {})

    st.update(host=host)
    save_state(st)
    print(f"\n完了: https://{host}/")


def put_tunnel(cf, cfg, conf):
    cf.req("PUT", f"/workers/scripts/{cfg['WORKER_NAME']}/secrets",
           {"name": "TUNNEL_CONFIG", "text": json.dumps(conf), "type": "secret_text"})


def cmd_set_tunnel(cfg, url):
    secret = os.environ.get("GATE_SECRET")
    if not secret:
        sys.exit("[x] GATE_SECRET が未設定です。")
    if not re.fullmatch(r"https://[a-z0-9-]+\.trycloudflare\.com", url):
        sys.exit(f"[x] 不正なトンネル URL: {url!r}")
    put_tunnel(CF(cfg), cfg, {"url": url, "secret": secret})
    print(f"[+] Worker のトンネル先を更新: {url}")


def cmd_clear_tunnel(cfg):
    put_tunnel(CF(cfg), cfg, {})
    print("[+] Worker をメンテナンス表示に切替")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None   # リダイレクト先に X-Gate-Secret を送らない (3xx は HTTPError として扱う)


def cmd_wait_ready(url, timeout=90):
    secret = os.environ.get("GATE_SECRET", "")
    if not re.fullmatch(r"https://[a-z0-9-]+\.trycloudflare\.com", url):
        sys.exit(f"[x] 不正なトンネル URL: {url!r}")
    opener = urllib.request.build_opener(_NoRedirect)
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            r = urllib.request.Request(url, method="HEAD", headers={"X-Gate-Secret": secret})
            with opener.open(r, timeout=10) as res:
                code = res.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:  # noqa: BLE001  DNS 未伝播など
            code, last = None, e
        if code and code < 500:
            print(f"[+] トンネル疎通 OK (HTTP {code})")
            return
        last = code or last
        time.sleep(3)
    print(f"[!] トンネル疎通を確認できませんでした (last={last})。続行します。", file=sys.stderr)


def cmd_status(cfg):
    st = load_state()
    if not st:
        sys.exit("未セットアップ")
    print(f"URL: https://{st['host']}/")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "wait-ready":
        return cmd_wait_ready(args[0])
    cfg = load_config()
    if cmd == "setup":
        cmd_setup(cfg)
    elif cmd == "set-tunnel":
        cmd_set_tunnel(cfg, args[0])
    elif cmd == "clear-tunnel":
        cmd_clear_tunnel(cfg)
    elif cmd == "status":
        cmd_status(cfg)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
