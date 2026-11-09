# Gate House

LAN 内でしか見られない Web アプリ（例: `http://app.internal.example`）を、
Cloudflare の **workers.dev の固定 URL** で外部から使えるようにする仕組みです。
アクセスできるのは許可リスト（`.env` または `allowed_emails.txt`）に登録したメールアドレスのユーザだけで、
ログインには **Google アカウント**（OAuth 2.0 / OpenID Connect）を使います。

- Cloudflare の有料機能・Zero Trust・独自ドメインは不要（クレジットカード登録不要）
- 必要なのは `cloudflared`、`python3`（標準ライブラリのみ）、`bash`、Google Cloud のプロジェクト（無料）

---

## 1. 仕組み

```
利用者のブラウザ
   │  https://gate-house.<サブドメイン>.workers.dev   ← 利用者に案内する固定 URL
   ▼
Cloudflare Worker（worker/worker.js）
   │  起動中のトンネル URL へ転送。起動ごとに変わる秘密ヘッダを付与
   │  停止中は「メンテナンス中」ページを表示
   ▼
https://xxxx.trycloudflare.com                       ← Quick Tunnel。起動のたびに URL が変わる
   ▼
cloudflared（このサーバ上）
   ▼
gatekeeper（lib/gatekeeper.py, 127.0.0.1:18787）
   │  ├ 秘密ヘッダが無い（トンネル URL への直接アクセス） → 403
   │  ├ 未ログイン → ログイン画面 /__auth/login → Google でログイン
   │  │             → /__auth/callback で検証し、許可リストと照合
   │  └ ログイン済み → 内部の Web アプリへ中継（X-Auth-Email ヘッダ付与。WebSocket も可）
   ▼
ORIGIN_URL（内部の Web アプリ）
```

Quick Tunnel の URL は起動のたびに変わります。そのため `scripts/start.sh` は起動時に Cloudflare API で
Worker の転送先を書き換えます。利用者からは常に同じ workers.dev の URL に見えます。

### ファイル構成

| パス | 内容 |
|---|---|
| `scripts/` | 操作用スクリプト（どのディレクトリから実行しても可） |
| `scripts/setup.sh` | 初期セットアップ / Worker の再デプロイ（何度実行しても可） |
| `scripts/start.sh` | gatekeeper とトンネルを起動し、Worker の転送先を更新 |
| `scripts/stop.sh` | Worker をメンテナンス表示に切り替え、プロセスを停止 |
| `allowed_emails.txt` | ログインを許可するメールアドレス一覧（場所は `ALLOWED_EMAILS_FILE` で変更可） |
| `.env.example` | 設定ファイルのひな形（`.env` にコピーして使用） |
| `worker/worker.js` | Cloudflare Worker のコード |
| `lib/gatekeeper.py` | 認証付きローカルプロキシ（cloudflared は gatekeeper の子プロセスとして起動） |
| `lib/cf.py` | Cloudflare API 操作 |
| `.state/` | 実行時の状態・ログ（自動生成、権限 700） |

---

## 2. 事前準備（初回のみ）

### 2.1 Cloudflare アカウントと workers.dev サブドメイン

1. <https://dash.cloudflare.com/sign-up> で Cloudflare アカウントを作成（無料プラン）
2. ダッシュボード左メニュー **Workers & Pages** を開き、workers.dev サブドメインを登録
   （例: `myname` → `*.myname.workers.dev`）
   - 既に登録済みなら不要です
3. **アカウント ID** を控える
   - ダッシュボードのホーム、またはアカウント名の右の **︙ → アカウント ID をコピー**

### 2.2 Cloudflare API トークン

1. 右上のアイコン → **My Profile** → **API Tokens** → **Create Token**
2. **Create Custom Token** を選び、以下を設定
   - Permissions: **Account / Workers Scripts / Edit**（これだけで可）
   - Account Resources: 使用するアカウントのみ
3. 作成されたトークンを控える（一度しか表示されません）

> このトークンはアカウント内のすべての Worker を編集できます。`.env` 以外に保存しないでください。

### 2.3 Google OAuth クライアント

1. <https://console.cloud.google.com/> でプロジェクトを作成（既存のものでも可）
2. **Google Auth Platform**（旧「OAuth 同意画面」）を開き、初期設定をする
   - アプリ名: 任意（ログイン時の Google の画面に表示されます）
   - 対象（Audience）:
     - Google Workspace の組織内だけで使う場合は **内部**
     - それ以外は **外部**。作成後に **公開ステータスを「本番環境」** にする
       （「テスト」のままだと、テストユーザに登録したアカウントしかログインできません）
   - スコープは追加不要です（`openid` と `email` のみ使用。Google の審査は不要）
3. **クライアント** → **クライアントを作成**
   - アプリケーションの種類: **ウェブ アプリケーション**
   - 承認済みのリダイレクト URI: `https://<WORKER_NAME>.<サブドメイン>.workers.dev/__auth/callback`
     （正確な値は `./scripts/setup.sh` の最後に表示されます。あとから追加しても構いません）
4. 表示された **クライアント ID** と **クライアント シークレット** を控える

---

## 3. セットアップ

### 3.1 設定ファイルの作成

```bash
cd ~/gate-house
./scripts/setup.sh          # 初回は .env を作成して終了します
```

`.env` を編集します。値は **シングルクォート** で囲んでください。

```bash
CF_API_TOKEN='（2.2 のトークン）'
CF_ACCOUNT_ID='（2.1 のアカウント ID）'
WORKER_NAME='gate-house'           # 公開 URL: https://gate-house.<サブドメイン>.workers.dev

GOOGLE_CLIENT_ID='（2.3 のクライアント ID）'
GOOGLE_CLIENT_SECRET='（2.3 のクライアント シークレット）'
GOOGLE_HD=''                         # 任意: Workspace ドメインに限定する場合 (例: example.ac.jp)

ALLOWED_EMAILS=''                    # 許可リスト (3.2 参照)
ALLOWED_EMAILS_FILE='allowed_emails.txt'

APP_NAME='Web アプリ'                # ログイン画面に表示する名前
SESSION_HOURS='24'                   # ログイン状態の有効時間
PUBLIC_URL=''                        # 任意: 空なら workers.dev の URL
COOKIE_NAME='gate-house'             # Cookie 名: __Host-gate-house_session など
ORIGIN_URL='http://app.internal.example'
GATE_PORT='18787'
```

`COOKIE_NAME` は英数字・`_`・`-` で 32 文字以内です。ゲートウェイの Cookie は `__Host-<COOKIE_NAME>_session` /
`__Host-<COOKIE_NAME>_oauth` になり、`__Host-<COOKIE_NAME>_` で始まる Cookie は内部アプリへ転送されません。
内部アプリが同じ名前の Cookie を使っている場合は変更してください。変更すると全員ログアウトになります。

`.env` には秘密情報が入ります。権限は自動で 600 に設定されます。共有や Git への追加はしないでください。

### 3.2 許可ユーザの登録

ログインを許可する Google アカウントのメールアドレスを登録します。登録方法は 2 つあり、
**両方に書いたアドレスを合わせたもの**が許可されます（どちらか一方だけでも構いません）。

| 方法 | 書き方 | 反映 |
|---|---|---|
| `.env` の `ALLOWED_EMAILS` | カンマまたは空白区切り | 再起動（`./scripts/stop.sh && ./scripts/start.sh`） |
| `ALLOWED_EMAILS_FILE` のファイル（既定 `allowed_emails.txt`） | 1 行に 1 アドレス | 保存するとすぐ |

`.env` に書く例:

```bash
ALLOWED_EMAILS='taro@gmail.com, hanako@example.ac.jp, @example.ac.jp'
ALLOWED_EMAILS_FILE='allowed_emails.txt'    # 相対パスはこのディレクトリ基準。絶対パスも可
```

ファイルに書く例:

```text
# コメントは # 以降
taro@gmail.com
hanako@example.ac.jp
@example.ac.jp      # @ から始めるとそのドメイン全体を許可
```

- 大文字・小文字は区別しません
- Google が **確認済み**（`email_verified`）としたアドレスだけを照合します
- 削除したユーザは、反映された時点で次の操作からログアウト扱いになります
- ファイルが無い（または読めない）場合は、ファイル分は 0 件として扱い、`.env` の `ALLOWED_EMAILS` だけで動きます。
  あとからファイルを作成すれば、その時点で読み込まれます
- どちらにも 1 件も登録されていないと起動しません

> ドメイン指定（`@example.ac.jp`）について: Google アカウントは Gmail 以外のアドレスでも作成できます。
> そのドメインのメールを受信できる人なら、Workspace 以外の個人 Google アカウントでもログインできます。
> 組織の Google Workspace アカウントに限りたい場合は、`.env` の `GOOGLE_HD` にドメインを設定してください。

### 3.3 Worker のデプロイ

```bash
./scripts/setup.sh
```

成功すると以下のように表示されます。`完了:` の URL が利用者に案内する固定 URL です。
最後の行の値を Google のクライアント設定の **承認済みのリダイレクト URI** に登録してください。

```
[+] cloudflared: /home/.../cloudflared (cloudflared version ...)
[+] Worker ホスト: gate-house.<サブドメイン>.workers.dev
[+] Worker デプロイ: gate-house
[+] workers.dev ルート有効 / Preview URL 無効

完了: https://gate-house.<サブドメイン>.workers.dev/

[+] Google の「承認済みのリダイレクト URI」に登録する値: https://gate-house.<サブドメイン>.workers.dev/__auth/callback
```

---

## 4. 起動と停止

### 起動

```bash
./scripts/start.sh
```

```
[+] gatekeeper 起動 (127.0.0.1:18787 -> http://app.internal.example)
[+] Quick Tunnel: https://xxxx-xxxx.trycloudflare.com
[+] トンネル疎通 OK (HTTP 401)
[+] Worker のトンネル先を更新: https://xxxx-xxxx.trycloudflare.com

公開URL: https://gate-house.<サブドメイン>.workers.dev/
```

- 起動ごとに秘密ヘッダの値を作り直し、Worker に登録します
- `trycloudflare.com` の URL は利用者に案内する必要はありません（直接アクセスしても 403 になります）
- ターミナルを閉じても動き続けます（バックグラウンド起動）

### 停止

```bash
./scripts/stop.sh
```

Worker を「メンテナンス中」表示に切り替えてから、gatekeeper と cloudflared を停止します。
Cloudflare API に繋がらない状況でプロセスだけ止めたいときは `./scripts/stop.sh --no-api` を使います。

### 再起動

```bash
./scripts/stop.sh && ./scripts/start.sh
```

ログイン状態は `.state/sessions.json` に保存されるため、再起動しても利用者はログインし直す必要はありません。

---

## 5. 利用者側の流れ

1. 案内された `https://gate-house.<サブドメイン>.workers.dev/` を開く
2. 「Google アカウントでログイン」を押し、Google のアカウント選択画面でアカウントを選ぶ
3. 許可されたアカウントなら Web アプリが表示される
4. ログアウトは `/__auth/logout` を開いて「ログアウトする」

制限:

| 項目 | 値 |
|---|---|
| Google でのログイン操作の有効期限 | 10 分 |
| 同じ IP からのログイン開始 | 10 分に 30 回 / 1 時間に 100 回 |
| 同じ IP からのログイン失敗（未許可アカウント含む） | 1 時間に 20 回 |
| WebSocket の同時接続数 | 64 |
| WebSocket の無通信タイムアウト | 1 時間 |
| ログイン状態の有効時間 | `SESSION_HOURS`（既定 24 時間） |

---

### WebSocket

内部アプリが WebSocket（`ws://` / `wss://`）を使っていても、そのまま利用できます。

- ログイン済みのユーザだけが接続できます。未ログインの接続要求は 401 になります
- 接続中もおよそ 1 分ごとにセッションと許可リストを確認し、ログアウトしたユーザや許可リストから削除したユーザの接続は切断します
- 他のサイトのページからの接続を防ぐため、`Origin` ヘッダが公開 URL 以外の接続要求は 403 で拒否します。
  中継先には `Origin` を `ORIGIN_URL` に書き換えて渡すため、内部アプリ側の同一オリジン検査はそのまま通ります
- アプリ側は公開 URL に合わせて `wss://<公開 URL のホスト>/...` へ接続する必要があります。
  `ws://内部ホスト名/...` のように内部の URL を直接書いているアプリは外部からは動きません
- Cloudflare は約 100 秒間データが流れない WebSocket を切断します。長時間つなぎっぱなしにするアプリは、ping などを定期的に送る作りにしてください

## 6. 日常の運用

| やりたいこと | 方法 |
|---|---|
| ユーザを追加・削除 | `allowed_emails.txt` を編集して保存（即時反映）、または `.env` の `ALLOWED_EMAILS` を編集して再起動 |
| 全員を強制ログアウト | `./scripts/stop.sh && rm .state/sessions.json && ./scripts/start.sh` |
| `worker/worker.js` を変更した | `./scripts/setup.sh`（再デプロイ） |
| Google の設定を確認 | `python3 -I lib/gatekeeper.py --check` |
| 稼働状況の確認 | `cat .state/tunnel_url`、`ps -p $(cat .state/gatekeeper.pid)` |
| ログを見る | `tail -f .state/gatekeeper.log`（ログイン・アクセス記録） |
| トンネルのログ | `.state/cloudflared.log` |

`gatekeeper.log` は追記され、10 MB を超えると起動時に `gatekeeper.log.1` へローテーションされます。

---

## 7. トラブルシューティング

| 症状 | 原因と対処 |
|---|---|
| `cloudflared が見つかりません` | `.env` に `CLOUDFLARED='/path/to/cloudflared'` を追加 |
| `workers.dev サブドメインが未登録です` | 2.1 の手順でサブドメインを登録 |
| `API ... HTTP 403` / `Authentication error` | API トークンの権限（Workers Scripts : Edit）とアカウント ID を確認 |
| `~/.cloudflared/config.yml があると…` | Quick Tunnel と競合するため、そのファイルを別名に退避 |
| `既に起動中です` | `./scripts/stop.sh` してから `./scripts/start.sh` |
| `GOOGLE_CLIENT_ID が未設定です` など | `.env` に 2.3 の値を記入 |
| `許可リストが空です` | `.env` の `ALLOWED_EMAILS` か `allowed_emails.txt` にアドレスを登録 |
| gatekeeper がすぐ終了する | `tail .state/gatekeeper.log`。`Address already in use` なら `GATE_PORT` を変更 |
| 公開 URL が「メンテナンス中」 | 停止中です。`./scripts/start.sh` |
| 公開 URL が「接続エラー」/ 502 | トンネルが落ちています。`./scripts/stop.sh && ./scripts/start.sh` |
| Google の画面で `redirect_uri_mismatch` | `./scripts/setup.sh` の最後に表示された URI を Google のクライアントに登録（反映に数分かかることあり） |
| Google の画面で「アクセスをブロック」/ `access_denied` | 同意画面が「テスト」のまま。本番環境に公開するか、テストユーザに追加 |
| 「ログインに失敗しました」 | `.state/gatekeeper.log` の `oauth FAILED` を確認。`invalid_client` ならクライアント シークレットの誤り |
| 「〜はアクセスを許可されていません」 | 許可リストにそのアドレスが無い。ログの `login DENIED` で実際のアドレスを確認 |
| ログイン後にアプリの一部が動かない | gatekeeper.log でエラーを確認。内部の URL（`http://内部ホスト名/...`）を直接参照していないかも確認 |
| WebSocket がつながらない | `./scripts/setup.sh` で Worker を再デプロイ済みか確認。ログの `websocket REJECTED bad origin` は公開 URL 以外からの接続、`origin websocket error` は中継先に接続できていない |

---

## 8. セキュリティ上の注意

- `.env`（API トークン・クライアント シークレット）と `.state/`（セッション情報）は他人に見せないこと
- 内部の Web アプリ本体（`ORIGIN_URL`）は、**LAN 内からは従来どおり認証なしで直接アクセスできます**。
  この仕組みが守るのは外部からのアクセス経路のみです
- 内部アプリはリクエストの `X-Auth-Email` ヘッダでログイン中のユーザを知ることができます。
  ただし LAN 内からの直接アクセスでは誰でも偽装できるため、このヘッダを LAN 側の認証には使わないでください
- cloudflared や gatekeeper が落ちても自動復帰はしません（外部からは 502 またはメンテナンス表示になり、安全側に倒れます）。
  常時運用する場合は systemd 等での監視・自動再起動を検討してください
