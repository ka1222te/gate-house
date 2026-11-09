// Gate House: workers.dev の固定URLから、起動ごとに変わる Quick Tunnel
// (trycloudflare.com) へリバースプロキシする。認証はローカルの gatekeeper が行う。
//
// env.TUNNEL_CONFIG (secret): {"url":"https://xxx.trycloudflare.com","secret":"..."}  start/stop で更新

const LENGTH_HEADER = "X-Gate-Length";   // gatekeeper が付ける本文の長さ (lib/gatekeeper.py と対)
const RETRIES = 3;

function page(status, title, msg) {
  return new Response(
    `<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem">
<h1>${title}</h1><p>${msg}</p></body></html>`,
    { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "retry-after": "60" } });
}

export default {
  async fetch(req, env) {
    let cfg = {};
    try { cfg = JSON.parse(env.TUNNEL_CONFIG || "{}"); } catch {}
    if (!cfg.url || !cfg.secret) return page(503, "メンテナンス中", "このサービスは現在停止中です。しばらくしてから再度アクセスしてください。");

    const inUrl = new URL(req.url);
    const upstream = new URL(cfg.url);
    // 想定外の転送先には秘密ヘッダを送らない
    if (upstream.protocol !== "https:" || !upstream.hostname.endsWith(".trycloudflare.com")) {
      return page(500, "設定エラー", "転送先の設定が不正です。");
    }
    // new URL(path, base) だと "//evil.example/..." がプロトコル相対 URL として別ホストに解決され、
    // 秘密ヘッダと Cookie が第三者に送られてしまう。転送先のオリジンを固定してパスだけ差し替える
    const target = new URL(upstream.origin);
    target.pathname = inUrl.pathname;
    target.search = inUrl.search;
    if (target.origin !== upstream.origin) {
      return new Response("Bad Request", { status: 400 });
    }

    const headers = new Headers(req.headers);
    headers.set("X-Gate-Secret", cfg.secret);
    headers.set("X-Gate-Client-IP", req.headers.get("cf-connecting-ip") || "");
    headers.set("X-Forwarded-Host", inUrl.host);
    headers.set("X-Forwarded-Proto", "https");

    // WebSocket: ハンドシェイクを gatekeeper へ転送し、101 応答はそのまま返す (以後のフレームは Cloudflare が中継)
    if ((req.headers.get("upgrade") || "").toLowerCase() === "websocket") {
      let ws;
      try {
        ws = await fetch(target, { method: "GET", headers });
      } catch (e) {
        return new Response("Bad Gateway", { status: 502 });
      }
      if (ws.status === 101) return ws;
      return new Response(ws.body, ws);   // 401 / 403 など
    }

    // 一斉に大量のファイルを取得すると、トンネル経由の本文が途中で切れたまま「正常終了」扱いになることがある
    // (ブラウザは切れた JS を immutable としてキャッシュし、ページが壊れ続ける)。
    // gatekeeper が付ける X-Gate-Length と実際の長さを照合し、合わなければ取り直す (GET のみ)。
    const init = {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? undefined : req.body,
      redirect: "manual",
      cache: "no-store",   // 認証前に Cloudflare のキャッシュから返さない
    };
    const tries = req.method === "GET" ? RETRIES : 1;   // ボディ付きのリクエストは再送できない
    let res = null, buf = null;
    for (let i = 0; i < tries; i++) {
      try {
        res = await fetch(target, init);
      } catch (e) {
        return page(502, "接続エラー", "トンネルに接続できませんでした。");
      }
      if (res.status === 530 || res.status === 1033) {
        return page(503, "メンテナンス中", "このサービスは現在停止中です。");
      }
      const want = res.headers.get(LENGTH_HEADER);
      if (want === null) break;   // 長さが付いていない応答 (大きい応答・SSE など) はそのまま中継
      try {
        const b = await res.arrayBuffer();
        if (b.byteLength === Number(want)) { buf = b; break; }
      } catch (e) {}
      res = null;
    }
    if (!res) {
      return page(502, "接続エラー", "トンネルからの応答が不完全でした。再読み込みしてください。");
    }

    const out = new Response(buf !== null ? buf : res.body, res);
    out.headers.delete(LENGTH_HEADER);
    out.headers.set("Strict-Transport-Security", "max-age=31536000");
    const loc = out.headers.get("location");
    if (loc && loc.startsWith(upstream.origin)) {
      out.headers.set("location", inUrl.origin + loc.slice(upstream.origin.length));
    }
    return out;
  },
};
