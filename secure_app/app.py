"""
NoteVault (SECURE BUILD)
========================
The fixed version of ../vulnerable_app/app.py for the CodeAlpha Task 3
Secure Coding Review. Same features, same pages, every finding remediated.
Each fix is tagged with the finding ID it closes, for example  # [FIX V-01]

Uses only Flask + the Python standard library, so there is nothing extra to
install. In production you would reach for Flask-WTF (CSRF) and Flask-Limiter
(rate limiting); the small hand-written versions here show what they do.
"""
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import shutil
import sqlite3
# Bandit B404 reviewed: subprocess is used only with a fixed argv, see ping()
import subprocess  # nosec B404
import time
from urllib.parse import urlsplit

from flask import (Flask, abort, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from markupsafe import Markup, escape
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "notevault.db")
FILES_DIR = os.path.join(BASE_DIR, "files")

app = Flask(__name__)
# [FIX V-01] secret comes from the environment; a random one is used otherwise
# (sessions then reset on restart, which is safe, never guessable).
app.secret_key = os.environ.get("NOTEVAULT_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,            # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",           # defence in depth against CSRF
    SESSION_COOKIE_SECURE=os.environ.get("NOTEVAULT_HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=1800,         # 30 minute sessions
    MAX_CONTENT_LENGTH=64 * 1024,            # reject oversized request bodies
)
log = logging.getLogger("notevault")

MIN_PASSWORD_LEN = 10
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


# ---------------------------------------------------------------- CSRF
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.context_processor
def template_helpers():
    def csrf_field():
        # Bandit B704 reviewed: server-generated token, escaped before wrapping
        return Markup('<input type="hidden" name="csrf_token" value="%s">'  # nosec B704
                      % escape(csrf_token()))
    return {"csrf_field": csrf_field, "build": "SECURE BUILD"}


@app.before_request
def check_csrf():
    # [FIX V-10] every state-changing request must carry the session's token
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf_token", "")):
            abort(400, "CSRF token missing or invalid")


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


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
    # [FIX V-03] salted, slow, memory-hard hash (scrypt) instead of bare MD5
    return generate_password_hash(password, method="scrypt")


def password_problem(password):
    # [FIX V-03] minimum password policy
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters"
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        return "Password must contain letters and digits"
    return None


def init_db():
    os.makedirs(FILES_DIR, exist_ok=True)
    with open(os.path.join(FILES_DIR, "welcome.txt"), "w") as f:
        f.write("Welcome to NoteVault! Files in this folder are shared.\n")
    # [FIX V-01] no hardcoded admin password: env var, or a random one shown once
    admin_password = os.environ.get("NOTEVAULT_ADMIN_PASSWORD")
    if not admin_password:
        admin_password = secrets.token_urlsafe(12)
        print(f"[init] generated admin password: {admin_password}")
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
               ("admin", hash_password(admin_password)))
    db.execute("INSERT INTO users (username, password) VALUES (?,?)",
               ("alice", hash_password("alice-demo-2026")))
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


def own_note_or_404(note_id, user):
    # [FIX V-05] every note lookup is scoped to the logged-in owner
    note = get_db().execute("SELECT * FROM notes WHERE id = ? AND owner_id = ?",
                            (note_id, user["id"])).fetchone()
    if not note:
        abort(404)       # 404, not 403: do not reveal that the id exists
    return note


# ---------------------------------------------------------------- rate limit
# [FIX V-11] lock a (client, username) pair after repeated failed logins
MAX_FAILS, WINDOW_SECONDS = 5, 300
_failed_logins = {}


def _fail_key(username):
    return (request.remote_addr or "?", username.lower())


def login_locked(username):
    now = time.time()
    recent = [t for t in _failed_logins.get(_fail_key(username), [])
              if now - t < WINDOW_SECONDS]
    _failed_logins[_fail_key(username)] = recent
    return len(recent) >= MAX_FAILS


def record_failed_login(username):
    _failed_logins.setdefault(_fail_key(username), []).append(time.time())


def safe_next(target):
    # [FIX V-09] only allow same-site relative paths such as /note/2
    if not target or not target.startswith("/") or target.startswith("//") \
            or "\\" in target:
        return url_for("index")
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return url_for("index")
    return target


# ---------------------------------------------------------------- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if login_locked(username):
            return render_template("login.html",
                                   error="Too many attempts. Try again later."), 429
        # [FIX V-02] parameterised query: input is data, never SQL
        user = get_db().execute("SELECT * FROM users WHERE username = ?",
                                (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            _failed_logins.pop(_fail_key(username), None)
            session.clear()                  # fresh session, no fixation
            session["user_id"] = user["id"]
            session.permanent = True
            return redirect(safe_next(request.args.get("next")))
        record_failed_login(username)
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return render_template("login.html",
                               error="Username: 3-32 letters, digits, _ . -"), 400
    problem = password_problem(password)
    if problem:
        return render_template("login.html", error=problem), 400
    try:
        get_db().execute("INSERT INTO users (username, password) VALUES (?,?)",
                         (username, hash_password(password)))
        get_db().commit()
    except sqlite3.IntegrityError:
        return render_template("login.html", error="Username taken"), 400
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
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    note = own_note_or_404(note_id, user)
    # [FIX V-04] template prints content with Jinja auto-escaping (no |safe)
    return render_template("note.html", note=note)


@app.route("/note/new", methods=["POST"])
def new_note():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    title = request.form.get("title", "")[:200]
    content = request.form.get("content", "")[:10000]
    get_db().execute("INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
                     (user["id"], title, content))
    get_db().commit()
    return redirect(url_for("index"))


@app.route("/note/<int:note_id>/delete", methods=["POST"])
def delete_note(note_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    own_note_or_404(note_id, user)
    get_db().execute("DELETE FROM notes WHERE id = ? AND owner_id = ?",
                     (note_id, user["id"]))
    get_db().commit()
    return redirect(url_for("index"))


# ---------------------------------------------------------------- tools
def valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOST_RE.match(host))


@app.route("/tools/ping")
def ping():
    if not current_user():
        return redirect(url_for("login"))
    host = request.args.get("host", "127.0.0.1").strip()
    # [FIX V-06] strict allow-list validation + argument list, no shell
    if not valid_host(host):
        return render_template("tool.html", title="Ping",
                               output="Invalid host name or IP address"), 400
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    ping_exe = shutil.which("ping")              # absolute path, not PATH lookup
    if not ping_exe:
        return render_template("tool.html", title="Ping", output="ping unavailable"), 503
    try:
        # Bandit B603 reviewed: fixed argv, shell=False, host allow-listed above
        output = subprocess.run([ping_exe, count_flag, "1", host],  # nosec B603
                                shell=False, capture_output=True, text=True,
                                timeout=10).stdout
    except subprocess.TimeoutExpired:
        output = "Ping timed out"
    return render_template("tool.html", title="Ping", output=output)


@app.route("/download")
def download():
    if not current_user():
        return redirect(url_for("login"))
    name = request.args.get("file", "welcome.txt")
    # [FIX V-07] send_from_directory refuses any path that escapes FILES_DIR
    return send_from_directory(FILES_DIR, name, as_attachment=True)


@app.route("/import", methods=["POST"])
def import_notes():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # [FIX V-08] JSON is data only; it can never execute code. Validate shape.
    try:
        notes = json.loads(request.form.get("backup", ""))
        if not isinstance(notes, list) or len(notes) > 100:
            raise ValueError
        rows = []
        for item in notes:
            title, content = item["title"], item["content"]
            if not isinstance(title, str) or not isinstance(content, str):
                raise ValueError
            rows.append((user["id"], title[:200], content[:10000]))
    except (ValueError, KeyError, TypeError):
        return render_template("tool.html", title="Import",
                               output="Invalid backup format"), 400
    get_db().executemany(
        "INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)", rows)
    get_db().commit()
    return redirect(url_for("index"))


@app.route("/export")
def export_notes():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = get_db().execute("SELECT title, content FROM notes WHERE owner_id = ?",
                            (user["id"],)).fetchall()
    blob = json.dumps([{"title": r["title"], "content": r["content"]} for r in rows])
    return render_template("tool.html", title="Backup (JSON)", output=blob)


@app.errorhandler(500)
def server_error(e):
    # [FIX V-12] log the details server-side, show the user a generic message
    log.exception("Unhandled error: %s", getattr(e, "original_exception", e))
    return "<h1>Something went wrong</h1><p>The error has been logged.</p>", 500


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    # [FIX V-12] debug is off unless explicitly enabled for local development
    app.run(host="127.0.0.1", port=5001,
            debug=os.environ.get("NOTEVAULT_DEBUG") == "1")
