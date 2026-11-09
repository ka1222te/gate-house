#!/usr/bin/env bash
# ゲートキーパー + Quick Tunnel を起動し、Worker のトンネル先を更新
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
source ./.env
# cloudflared の場所 (.env の CLOUDFLARED > PATH > ~/.local/bin > /usr/local/bin)
CLOUDFLARED=${CLOUDFLARED:-$(command -v cloudflared || true)}
for c in "$HOME/.local/bin/cloudflared" /usr/local/bin/cloudflared /usr/bin/cloudflared; do
  [[ -n $CLOUDFLARED ]] && break
  [[ -x $c ]] && CLOUDFLARED=$c
done
[[ -x ${CLOUDFLARED:-} ]] || { echo "[x] cloudflared が見つかりません (.env に CLOUDFLARED=/path/to/cloudflared を設定)"; exit 1; }
STATE=.state
mkdir -p "$STATE"; chmod 700 "$STATE"
[[ -f $STATE/cloudflare.json ]] || { echo "[x] 先に ./scripts/setup.sh を実行してください"; exit 1; }

# 他ユーザから改ざん・閲覧されないように
chmod 600 .env
chmod go-w . lib lib/*.py worker worker/*.js scripts scripts/*.sh
ALLOW_FILE=${ALLOWED_EMAILS_FILE:-allowed_emails.txt}
[[ -f $ALLOW_FILE ]] && chmod go-w "$ALLOW_FILE"

# Google OAuth 設定の確認
python3 -I lib/gatekeeper.py --check >/dev/null || { python3 -I lib/gatekeeper.py --check; exit 1; }

alive() { [[ -f $1 ]] && kill -0 "$(cat "$1")" 2>/dev/null; }
if alive $STATE/cloudflared.pid || alive $STATE/gatekeeper.pid; then
  echo "[x] 既に起動中です (./scripts/stop.sh で停止)"; exit 1
fi

# ログローテーション (gatekeeper.log は追記で監査用に残す)
rotate() { [[ -f $1 && $(stat -c %s "$1") -gt 10485760 ]] && mv -f "$1" "$1.1" || true; }
rotate "$STATE/gatekeeper.log"
[[ -f $STATE/cloudflared.log ]] && mv -f "$STATE/cloudflared.log" "$STATE/cloudflared.log.1"

# 起動ごとに新しい共有シークレット
GATE_SECRET=$(python3 -I -c 'import secrets;print(secrets.token_urlsafe(48))')
export GATE_SECRET

# 失敗時は起動したものを止める
cleanup_on_fail() { echo "[x] 起動に失敗しました。ログ: $STATE/*.log"; scripts/stop.sh --no-api >/dev/null 2>&1 || true; }
trap cleanup_on_fail ERR

# 1) ゲートキーパー + Quick Tunnel
#    cloudflared は gatekeeper の子プロセスとして起動し、gatekeeper が落ちると即座に kill される
#    (秘密ヘッダは cloudflared には渡さない)
: >"$STATE/cloudflared.log"
CLOUDFLARED="$CLOUDFLARED" nohup python3 -I lib/gatekeeper.py >>"$STATE/gatekeeper.log" 2>&1 &
echo $! >"$STATE/gatekeeper.pid"
sleep 1
alive $STATE/gatekeeper.pid || { tail -5 "$STATE/gatekeeper.log"; false; }
echo "[+] gatekeeper 起動 (127.0.0.1:${GATE_PORT:-18787} -> $ORIGIN_URL)"

URL=""
for _ in $(seq 1 60); do
  URL=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$STATE/cloudflared.log" | head -1 || true)
  [[ -n $URL ]] && break
  alive $STATE/gatekeeper.pid || break
  sleep 1
done
[[ -n $URL ]] || { tail -20 "$STATE/cloudflared.log"; false; }
echo "$URL" >"$STATE/tunnel_url"
echo "[+] Quick Tunnel: $URL"

# 3) 疎通待ち -> Worker 更新
python3 -I lib/cf.py wait-ready "$URL"
python3 -I lib/cf.py set-tunnel "$URL"
trap - ERR

HOST=$(python3 -I -c 'import json;print(json.load(open(".state/cloudflare.json"))["host"])')
echo
echo "公開URL: https://$HOST/"
