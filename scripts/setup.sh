#!/usr/bin/env bash
# Worker の初期セットアップ (何度実行しても可)
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -f .env ]]; then
  cp .env.example .env && chmod 600 .env
  echo ".env を作成しました。CF_API_TOKEN / CF_ACCOUNT_ID / ORIGIN_URL を記入して再実行してください。"
  exit 1
fi
chmod 600 .env
source ./.env
# cloudflared の場所 (.env の CLOUDFLARED > PATH > ~/.local/bin > /usr/local/bin)
CLOUDFLARED=${CLOUDFLARED:-$(command -v cloudflared || true)}
for c in "$HOME/.local/bin/cloudflared" /usr/local/bin/cloudflared /usr/bin/cloudflared; do
  [[ -n $CLOUDFLARED ]] && break
  [[ -x $c ]] && CLOUDFLARED=$c
done
[[ -x ${CLOUDFLARED:-} ]] || { echo "[x] cloudflared が見つかりません (.env に CLOUDFLARED=/path/to/cloudflared を設定)"; exit 1; }
echo "[+] cloudflared: $CLOUDFLARED ($("$CLOUDFLARED" --version 2>&1 | head -1))"
if [[ -f ~/.cloudflared/config.yml || -f ~/.cloudflared/config.yaml ]]; then
  echo "[!] ~/.cloudflared/config.yml があると Quick Tunnel が起動しません。退避してください。"
fi
python3 -I lib/cf.py setup
echo
python3 -I lib/gatekeeper.py --check || true
