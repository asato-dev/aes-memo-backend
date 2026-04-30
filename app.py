"""
app.py - Flask 製メモアプリ エントリーポイント

ユーザー認証（登録・ログイン・ログアウト）と、
AES-256-CBC 暗号化によるメモの保存・取得・削除機能を提供する REST API サーバー。

セキュリティ設計:
    - パスワード: bcrypt（ソルト自動付与）でハッシュ化
    - メモ本文: AES-256-CBC（ランダム IV）で暗号化してDBに保存
    - SQL インジェクション対策: psycopg2 のプレースホルダ（%s）を使用
    - 認可: login_required デコレータでエンドポイントを保護
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps

from database import init_db, get_db
from aes import aes_encrypt, aes_decrypt

import os
import bcrypt
import psycopg2


# ================================================================
# アプリケーション初期化
# ================================================================

app = Flask(__name__)

_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    raise RuntimeError("環境変数 SECRET_KEY が設定されていません")
app.secret_key = _secret_key

_raw_key = os.environ.get("AES_KEY")
if not _raw_key:
    raise RuntimeError("環境変数 AES_KEY が設定されていません")
AES_KEY = _raw_key.encode()[:32].ljust(32, b"0")

# アプリ起動時にテーブルが存在しない場合は自動作成する
with app.app_context():
    init_db()


# ================================================================
# ユーティリティ
# ================================================================

def hash_password(password: str) -> str:
    """パスワードを bcrypt でハッシュ化して返す（ソルトは自動付与）。"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password: str, hashed: str) -> bool:
    """入力パスワードと bcrypt ハッシュを照合する。"""
    return bcrypt.checkpw(password.encode(), hashed.encode())


def login_required(f):
    """未ログイン時にログインページへリダイレクトするデコレータ。"""
    @wraps(f)  # 元の関数名・docstring をデコレータ適用後も保持する
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ================================================================
# ページルーティング
# ================================================================

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


# ================================================================
# 認証 API
# ================================================================

@app.route("/api/register", methods=["POST"])
def register():
    """ユーザー登録 API。パスワードは bcrypt でハッシュ化して保存する。"""
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "ユーザー名とパスワードを入力してください"}), 400

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (username, hash_password(password))
        )
        conn.commit()
        cur.close()
        return jsonify({"message": "登録成功"})
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return jsonify({"error": "このユーザー名は既に使われています"}), 400
    except Exception:
        conn.rollback()
        return jsonify({"error": "登録に失敗しました"}), 500
    finally:
        conn.close()


@app.route("/api/login", methods=["POST"])
def login():
    """
    ログイン API。

    username でユーザーを取得後、bcrypt.checkpw でパスワードを照合する。
    username と password を同時に WHERE 句で検索しない理由:
        bcrypt ハッシュは照合に checkpw が必要なため、DB 側で直接比較できない。
    """
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = get_db()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s", (username,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if not user or not check_password(password, user["password"]):
        return jsonify({"error": "ユーザー名またはパスワードが違います"}), 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return jsonify({"message": "ログイン成功"})


@app.route("/api/logout", methods=["POST"])
def logout():
    """ログアウト API。セッションを全消去する。"""
    session.clear()
    return jsonify({"message": "ログアウトしました"})


# ================================================================
# メモ API
# ================================================================

@app.route("/api/memos", methods=["GET"])
@login_required
def get_memos():
    """
    ログインユーザーのメモ一覧を取得する API。

    DB に保存された暗号文を aes_decrypt で復号してから返す。
    復号に失敗した場合はフォールバック文字列を返す。
    """
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "SELECT id, title, content, created_at FROM memos"
        " WHERE user_id=%s ORDER BY created_at DESC",
        (session["user_id"],)
    )
    memos = cur.fetchall()
    cur.close()
    conn.close()

    result = []
    for m in memos:
        try:
            decrypted = aes_decrypt(m["content"], AES_KEY)
        except Exception:
            decrypted = "（復号失敗）"
        result.append({
            "id":         m["id"],
            "title":      m["title"],
            "content":    decrypted,
            "created_at": str(m["created_at"]),
        })
    return jsonify(result)


@app.route("/api/memos", methods=["POST"])
@login_required
def create_memo():
    """
    メモを作成する API。

    本文を AES-256-CBC で暗号化（IV はランダム生成）してから DB に保存する。
    """
    data    = request.get_json()
    title   = data.get("title",   "").strip()
    content = data.get("content", "").strip()

    if not title or not content:
        return jsonify({"error": "タイトルと内容を入力してください"}), 400

    encrypted = aes_encrypt(content, AES_KEY)

    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "INSERT INTO memos (user_id, title, content) VALUES (%s, %s, %s)",
        (session["user_id"], title, encrypted)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "保存しました"})


@app.route("/api/memos/<int:memo_id>", methods=["DELETE"])
@login_required
def delete_memo(memo_id):
    """
    指定 ID のメモを削除する API。

    WHERE 句に user_id を含めることで、他ユーザーのメモを削除できないようにする。
    """
    conn = get_db()
    cur  = conn.cursor()
    cur.execute(
        "DELETE FROM memos WHERE id=%s AND user_id=%s",
        (memo_id, session["user_id"])
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "削除しました"})


# ================================================================
# エントリーポイント
# ================================================================

if __name__ == "__main__":
    app.run(debug=False)
