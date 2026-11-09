#!/usr/bin/env bash
# Worker をメンテナンス表示に切替え、トンネルとゲートキーパーを停止
#   --no-api : Cloudflare API を呼ばずにプロセスだけ止める
set -uo pipefail
cd "$(dirname "$0")/.."
STATE=.state

if [[ ${1:-} != --no-api && -f $STATE/cloudflare.json ]]; then
  python3 -I lib/cf.py clear-tunnel || echo "[!] Worker の更新に失敗 (プロセス停止は続行)"
fi

for name in gatekeeper cloudflared; do   # gatekeeper を止めると cloudflared も連動して終了
  pidf=$STATE/$name.pid
  if [[ -f $pidf ]]; then
    pid=$(cat "$pidf")
    # PID 再利用で無関係なプロセスを kill しないようコマンド名を確認
    pat=$([[ $name == gatekeeper ]] && echo gatekeeper.py || echo cloudflared)
    if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && tr '\0' ' ' </proc/$pid/cmdline | grep -q "$pat"; then
      kill "$pid"
      for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
      kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
      echo "[+] $name 停止 (pid $pid)"
    fi
    rm -f "$pidf"
  fi
done
rm -f "$STATE/tunnel_url"
