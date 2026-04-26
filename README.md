# AES-256-CBC 暗号化メモアプリ

AES-256-CBC 暗号化をゼロから実装し、メモの保存・取得・削除機能を提供する Web アプリケーション。  
外部暗号ライブラリ（PyCryptodome 等）を使わず、Python 標準ライブラリのみで AES を実装した。

---

## 技術スタック

| レイヤー | 技術 |
|----------|------|
| バックエンド | Python / Flask |
| データベース | PostgreSQL（Supabase） |
| 暗号化 | AES-256-CBC（ゼロ実装） |
| 認証 | bcrypt（パスワードハッシュ） |

---

## 実装した暗号アルゴリズム

### AES-256-CBC（`aes.py`）

外部ライブラリを一切使わず、FIPS 197 仕様に基づいて実装した。

| コンポーネント | 実装内容 |
|----------------|----------|
| SubBytes / InvSubBytes | GF(2^8) 上の乗法逆元＋アフィン変換による S-Box |
| ShiftRows / InvShiftRows | 4×4 状態行列の行循環シフト |
| MixColumns / InvMixColumns | GF(2^8) 上の行列乗算（xtime による高速実装） |
| AddRoundKey | 状態とラウンド鍵の XOR |
| Key Expansion | Rijndael 鍵スケジュール（AES-256: 14 ラウンド） |
| CBC モード | ランダム IV を暗号文先頭に付加 |
| パディング | PKCS#7 |

**IV の扱い:**  
`os.urandom(16)` で暗号化ごとにランダムな IV を生成し、復号に必要なため暗号文の先頭 16 バイトに付加して保存する。  
出力フォーマット: `Base64( IV[16 bytes] + ciphertext )`

### パスワード認証（`app.py`）

- **bcrypt** でハッシュ化（ソルト自動付与）
- ログイン時は `bcrypt.checkpw` で照合し、DB 側での平文比較を行わない

---

## セキュリティ設計

| 脅威 | 対策 |
|------|------|
| パスワード漏洩 | bcrypt（コストファクター付きハッシュ） |
| メモ内容の漏洩 | AES-256-CBC 暗号化（ランダム IV） |
| SQL インジェクション | psycopg2 プレースホルダ（`%s`）で完全分離 |
| 不正アクセス | `login_required` デコレータ＋セッション管理 |
| 他ユーザーのメモ操作 | DELETE/SELECT 時に `AND user_id=%s` で制限 |

---

## ファイル構成

```
.
├── app.py          # Flask アプリ本体（認証 API・メモ API）
├── aes.py          # AES-256-CBC ゼロ実装
├── database.py     # PostgreSQL 接続・テーブル初期化
├── requirements.txt
└── templates/
    ├── index.html
    ├── login.html
    └── register.html
```

---

## セットアップ

### 必要環境

- Python 3.10 以上
- PostgreSQL（または Supabase）

### インストール

```bash
pip install -r requirements.txt
```

### 環境変数

`.env` ファイルをプロジェクトルートに作成する。

```env
DATABASE_URL=postgresql://user:password@host:5432/dbname
SECRET_KEY=your-random-secret-key
AES_KEY=your-32-byte-aes-key-here-padded0
```

| 変数 | 説明 |
|------|------|
| `DATABASE_URL` | PostgreSQL 接続 URL |
| `SECRET_KEY` | Flask セッション暗号化鍵（本番では必ずランダム文字列に変更） |
| `AES_KEY` | AES 暗号化鍵（32 バイト。不足分は `0` で補完） |

### 起動

```bash
python app.py
```

---

## API エンドポイント

### 認証

| メソッド | パス | 説明 |
|----------|------|------|
| POST | `/api/register` | ユーザー登録 |
| POST | `/api/login` | ログイン |
| POST | `/api/logout` | ログアウト |

### メモ（要ログイン）

| メソッド | パス | 説明 |
|----------|------|------|
| GET | `/api/memos` | メモ一覧取得（自分のメモのみ・作成日降順） |
| POST | `/api/memos` | メモ作成（本文を AES 暗号化して保存） |
| DELETE | `/api/memos/<id>` | メモ削除（自分のメモのみ削除可） |

---

## 注意事項

本リポジトリは**暗号アルゴリズムの学習・理解を目的**として実装したものです。  
AES の実装は FIPS 197 仕様に準拠していますが、サイドチャネル攻撃対策（定数時間実装等）は行っていません。  
本番運用には `cryptography` ライブラリ等の検証済み実装を使用してください。

---

## 動作環境

Python 3.10 以上 / Flask 3.x / PostgreSQL 14 以上
