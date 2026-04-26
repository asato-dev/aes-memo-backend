"""
database.py - データベース接続・初期化モジュール

PostgreSQL への接続と、アプリが必要とするテーブルの初期作成を行う。
接続情報は環境変数 DATABASE_URL から取得する。
"""

import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
    """
    データベース接続を生成して返す。

    カラム名をキーとする辞書形式でレコードを扱えるよう RealDictCursor を使用する。
    呼び出し元は使用後に conn.close() を呼ぶこと。
    """
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=psycopg2.extras.RealDictCursor
    )


def init_db():
    """
    アプリが必要とするテーブルを初期作成する。

    既にテーブルが存在する場合は何もしない（IF NOT EXISTS）。
    """
    conn = get_db()
    cur  = conn.cursor()

    # ユーザーテーブル: username は一意制約で重複登録を防ぐ
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       SERIAL PRIMARY KEY,
            username TEXT   NOT NULL UNIQUE,
            password TEXT   NOT NULL
        );
    """)

    # メモテーブル: user_id は users.id への外部キー
    # ON DELETE CASCADE でユーザー削除時にメモも連鎖削除される
    cur.execute("""
        CREATE TABLE IF NOT EXISTS memos (
            id         SERIAL PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title      TEXT    NOT NULL,
            content    TEXT    NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
