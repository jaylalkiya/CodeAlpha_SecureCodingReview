"""
NoteVault (VULNERABLE BUILD)
============================
A small Flask note-taking app written with common security mistakes ON PURPOSE.
It is the audit target for the CodeAlpha Task 3 Secure Coding Review.

!! DO NOT DEPLOY. Run only on localhost for learning. !!
Every planted bug is tagged with its finding ID, for example  # [V-01]
The fixed version lives in ../secure_app/app.py
"""
import base64
import hashlib
import os
import pickle
import sqlite3
import subprocess

from flask import (Flask, g, redirect, render_template, request,
                   send_file, session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "notevault.db")
FILES_DIR = os.path.join(BASE_DIR, "files")

app = Flask(__name__)
app.secret_key = "notevault-dev-key-123"          # [V-01] hardcoded secret key
ADMIN_PASSWORD = "admin123"                       # [V-01] hardcoded credential


@app.context_processor
def template_helpers():
    # Shared templates call csrf_field(); this build has no CSRF protection.
    return {"csrf_field": lambda: "", "build": "VULNERABLE BUILD"}


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()   # [V-03] MD5, no salt


def init_db():
    os.makedirs(FILES_DIR, exist_ok=True)
    with open(os.path.join(FILES_DIR, "welcome.txt"), "w") as f:
        f.write("Welcome to NoteVault! Files in this folder are shared.\n")
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER,
                            title TEXT, content TEXT);
    """)
    db.execute("INSERT INTO users (username, password, is_admin) VALUES (?,?,1)",
               ("admin", hash_password(ADMIN_PASSWORD)))
    db.execute("INSERT INTO users (username, password) VALUES (?,?)",
               ("alice", hash_password("alice2026")))
    db.execute("INSERT INTO notes (owner_id, title, content) VALUES (1,?,?)",
               ("Server root password", "prod-db root / S3cr3t!Pa55"))
    db.execute("INSERT INTO notes (owner_id, title, content) VALUES (2,?,?)",
               ("Shopping", "milk, eggs, coffee"))
    db.commit()
    db.close()


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?",
                            (session["user_id"],)).fetchone()


# ---------------------------------------------------------------- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # [V-02] SQL injection: user input pasted straight into the query
        query = ("SELECT * FROM users WHERE username = '" + username +
                 "' AND password = '" + hash_password(password) + "'")
        user = get_db().execute(query).fetchone()
        if user:
            session["user_id"] = user["id"]
            # [V-09] open redirect: 'next' is never checked
            return redirect(request.args.get("next") or url_for("index"))
        error = "Invalid username or password"      # [V-11] no rate limit
    return render_template("login.html", error=error)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")   # [V-03] no password policy
    try:
        get_db().execute("INSERT INTO users (username, password) VALUES (?,?)",
                         (username, hash_password(password)))
        get_db().commit()
    except sqlite3.IntegrityError:
        return render_template("login.html", error="Username taken")
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- notes
@app.route("/")
def index():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    notes = get_db().execute("SELECT * FROM notes WHERE owner_id = ?",
                             (user["id"],)).fetchall()
    return render_template("index.html", user=user, notes=notes)


@app.route("/note/<int:note_id>")
def view_note(note_id):
    if not current_user():
        return redirect(url_for("login"))
    # [V-05] IDOR: any logged-in user can read any note by changing the id
    note = get_db().execute("SELECT * FROM notes WHERE id = ?",
                            (note_id,)).fetchone()
    if not note:
        return "Not found", 404
    return render_template("note.html", note=note)   # [V-04] rendered |safe


@app.route("/note/new", methods=["POST"])
def new_note():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # [V-10] no CSRF token on a state-changing request
    get_db().execute("INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
                     (user["id"], request.form.get("title", ""),
                      request.form.get("content", "")))
    get_db().commit()
    return redirect(url_for("index"))


@app.route("/note/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id):
    if not current_user():
        return redirect(url_for("login"))
    # [V-05] IDOR + [V-10] no CSRF: deletes anyone's note
    get_db().execute("DELETE FROM notes WHERE id = ?", (note_id,))
    get_db().commit()
    return redirect(url_for("index"))


# ---------------------------------------------------------------- tools
@app.route("/tools/ping")
def ping():
    if not current_user():
        return redirect(url_for("login"))
    host = request.args.get("host", "127.0.0.1")
    # [V-06] OS command injection: shell=True with user input
    output = subprocess.run("ping -n 1 " + host, shell=True,
                            capture_output=True, text=True, timeout=10).stdout
    return render_template("tool.html", title="Ping", output=output)


@app.route("/download")
def download():
    if not current_user():
        return redirect(url_for("login"))
    name = request.args.get("file", "welcome.txt")
    # [V-07] path traversal: ../ walks out of the files folder
    return send_file(os.path.join(FILES_DIR, name))


@app.route("/import", methods=["POST"])
def import_notes():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    blob = request.form.get("backup", "")
    # [V-08] insecure deserialization: pickle runs attacker code on load
    notes = pickle.loads(base64.b64decode(blob))
    for title, content in notes:
        get_db().execute("INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
                         (user["id"], title, content))
    get_db().commit()
    return redirect(url_for("index"))


@app.route("/export")
def export_notes():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = get_db().execute("SELECT title, content FROM notes WHERE owner_id = ?",
                            (user["id"],)).fetchall()
    blob = base64.b64encode(pickle.dumps([tuple(r) for r in rows])).decode()
    return render_template("tool.html", title="Backup (base64 pickle)", output=blob)


@app.errorhandler(500)
def server_error(e):
    # [V-12] leaks internal error details to the user
    return "<h1>Server error</h1><pre>" + str(e.original_exception) + "</pre>", 500


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)   # [V-12] debug mode on
