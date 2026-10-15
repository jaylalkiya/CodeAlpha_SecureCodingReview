"""
Proof-of-concept tests for every finding in the Secure Coding Review.

Each finding has two tests:
  test_vXX_..._vulnerable  -> the attack WORKS against vulnerable_app
  test_vXX_..._secure      -> the same attack is BLOCKED by secure_app

Run from the SecureCodingReview folder:   python -m pytest -v
All attacks are harmless (they read data or create a marker file) and run
against a throwaway database in a temp folder.
"""
import base64
import importlib.util
import os
import pathlib
import pickle
import re
import sqlite3
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_app(folder, tmp_path):
    spec = importlib.util.spec_from_file_location(f"{folder}_app",
                                                  ROOT / folder / "app.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod          # lets Flask locate the templates folder
    spec.loader.exec_module(mod)
    mod.DB_PATH = str(tmp_path / "test.db")
    mod.FILES_DIR = str(tmp_path / "files")
    mod.app.config["TESTING"] = True
    mod.init_db()
    return mod


@pytest.fixture
def vuln(tmp_path):
    return load_app("vulnerable_app", tmp_path)


@pytest.fixture
def secure(tmp_path, monkeypatch):
    monkeypatch.setenv("NOTEVAULT_ADMIN_PASSWORD", "Adm1n-test-pass")
    return load_app("secure_app", tmp_path)


def token(client, path="/login"):
    """Fetch a page and pull out its CSRF token (None on the vulnerable build)."""
    m = re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).text)
    return m.group(1) if m else None


def post(client, url, data, page="/"):
    data = dict(data)
    t = token(client, page)
    if t:
        data["csrf_token"] = t
    return client.post(url, data=data)


def login(mod, username, password):
    client = mod.app.test_client()
    post(client, "/login", {"username": username, "password": password}, "/login")
    return client


ALICE_VULN = ("alice", "alice2026")
ALICE_SECURE = ("alice", "alice-demo-2026")


# ------------------------------------------------ V-01 hardcoded secret key
def forged_admin_cookie(app, key):
    """Sign {'user_id': 1} with a guessed key, the way Flask signs sessions."""
    real_key = app.secret_key
    app.secret_key = key
    serializer = app.session_interface.get_signing_serializer(app)
    app.secret_key = real_key
    return serializer.dumps({"user_id": 1})


def test_v01_hardcoded_secret_vulnerable(vuln):
    client = vuln.app.test_client()
    client.set_cookie("session", forged_admin_cookie(vuln.app, "notevault-dev-key-123"))
    page = client.get("/note/1").text
    assert "S3cr3t!Pa55" in page          # forged session = logged in as admin


def test_v01_hardcoded_secret_secure(secure):
    client = secure.app.test_client()
    client.set_cookie("session", forged_admin_cookie(secure.app, "notevault-dev-key-123"))
    resp = client.get("/note/1")
    assert resp.status_code == 302        # forged cookie rejected -> login page


# ------------------------------------------------ V-02 SQL injection
def test_v02_sql_injection_vulnerable(vuln):
    client = login(vuln, "admin' --", "anything")
    assert "Server root password" in client.get("/").text


def test_v02_sql_injection_secure(secure):
    client = login(secure, "admin' --", "anything")
    assert client.get("/").status_code == 302


# ------------------------------------------------ V-03 weak password storage
def stored_hash(mod, username):
    db = sqlite3.connect(mod.DB_PATH)
    row = db.execute("SELECT password FROM users WHERE username=?", (username,)).fetchone()
    db.close()
    return row[0]


def test_v03_weak_hashing_vulnerable(vuln):
    assert re.fullmatch(r"[0-9a-f]{32}", stored_hash(vuln, "alice"))   # bare MD5
    client = vuln.app.test_client()
    post(client, "/register", {"username": "bob", "password": "1"}, "/login")
    assert stored_hash(vuln, "bob")                                    # "1" accepted


def test_v03_weak_hashing_secure(secure):
    assert stored_hash(secure, "alice").startswith("scrypt:")
    client = secure.app.test_client()
    resp = post(client, "/register", {"username": "bob", "password": "1"}, "/login")
    assert resp.status_code == 400


# ------------------------------------------------ V-04 stored XSS
XSS = "<script>alert('xss')</script>"


def xss_page(mod, alice):
    client = login(mod, *alice)
    post(client, "/note/new", {"title": "x", "content": XSS})
    note_id = re.findall(r'href="/note/(\d+)"', client.get("/").text)[-1]
    return client.get(f"/note/{note_id}").text


def test_v04_stored_xss_vulnerable(vuln):
    assert XSS in xss_page(vuln, ALICE_VULN)


def test_v04_stored_xss_secure(secure):
    page = xss_page(secure, ALICE_SECURE)
    assert XSS not in page and "&lt;script&gt;" in page


# ------------------------------------------------ V-05 IDOR
def test_v05_idor_vulnerable(vuln):
    client = login(vuln, *ALICE_VULN)
    assert "S3cr3t!Pa55" in client.get("/note/1").text      # admin's note
    client.post("/note/1/delete")
    assert sqlite3.connect(vuln.DB_PATH).execute(
        "SELECT COUNT(*) FROM notes WHERE id=1").fetchone()[0] == 0


def test_v05_idor_secure(secure):
    client = login(secure, *ALICE_SECURE)
    assert client.get("/note/1").status_code == 404
    post(client, "/note/1/delete", {})
    assert sqlite3.connect(secure.DB_PATH).execute(
        "SELECT COUNT(*) FROM notes WHERE id=1").fetchone()[0] == 1


# ------------------------------------------------ V-06 OS command injection
INJECT = "127.0.0.1 & echo PWNED-4242"


def test_v06_command_injection_vulnerable(vuln):
    client = login(vuln, *ALICE_VULN)
    assert "PWNED-4242" in client.get("/tools/ping", query_string={"host": INJECT}).text


def test_v06_command_injection_secure(secure):
    client = login(secure, *ALICE_SECURE)
    resp = client.get("/tools/ping", query_string={"host": INJECT})
    assert resp.status_code == 400 and "PWNED-4242" not in resp.text


# ------------------------------------------------ V-07 path traversal
def test_v07_path_traversal_vulnerable(vuln):
    client = login(vuln, *ALICE_VULN)
    resp = client.get("/download", query_string={"file": str(ROOT / "vulnerable_app" / "app.py")})
    assert b"secret_key" in resp.data
    resp = client.get("/download", query_string={"file": "../test.db"})
    assert resp.data.startswith(b"SQLite format 3")        # whole database stolen


def test_v07_path_traversal_secure(secure):
    client = login(secure, *ALICE_SECURE)
    assert client.get("/download", query_string={"file": "../test.db"}).status_code == 404
    assert client.get("/download", query_string={
        "file": str(ROOT / "secure_app" / "app.py")}).status_code == 404
    assert client.get("/download", query_string={"file": "welcome.txt"}).status_code == 200


# ------------------------------------------------ V-08 insecure deserialization
class Exploit:
    """Unpickling this object calls Path.touch(marker): proof of code execution."""
    def __init__(self, marker):
        self.marker = marker

    def __reduce__(self):
        return (pathlib.Path.touch, (pathlib.Path(self.marker),))


def test_v08_pickle_rce_vulnerable(vuln, tmp_path):
    marker = tmp_path / "pwned.txt"
    blob = base64.b64encode(pickle.dumps(Exploit(marker))).decode()
    vuln.app.config["PROPAGATE_EXCEPTIONS"] = False   # app crashes AFTER the payload ran
    client = login(vuln, *ALICE_VULN)
    client.post("/import", data={"backup": blob})
    assert marker.exists()                                  # attacker code ran


def test_v08_pickle_rce_secure(secure, tmp_path):
    marker = tmp_path / "pwned.txt"
    blob = base64.b64encode(pickle.dumps(Exploit(marker))).decode()
    client = login(secure, *ALICE_SECURE)
    resp = post(client, "/import", {"backup": blob})
    assert resp.status_code == 400 and not marker.exists()
    ok = post(client, "/import", {"backup": '[{"title": "t", "content": "c"}]'})
    assert ok.status_code == 302                            # real JSON backups work


# ------------------------------------------------ V-09 open redirect
def test_v09_open_redirect_vulnerable(vuln):
    resp = vuln.app.test_client().post(
        "/login?next=https://evil.example/phish",
        data={"username": "alice", "password": "alice2026"})
    assert resp.headers["Location"] == "https://evil.example/phish"


def test_v09_open_redirect_secure(secure):
    client = secure.app.test_client()
    for bad in ("https://evil.example/phish", "//evil.example", "/\\evil.example"):
        client = secure.app.test_client()
        t = token(client)
        resp = client.post("/login", query_string={"next": bad}, data={
            "username": "alice", "password": "alice-demo-2026", "csrf_token": t})
        assert "evil.example" not in resp.headers["Location"]


# ------------------------------------------------ V-10 CSRF
def test_v10_csrf_vulnerable(vuln):
    client = login(vuln, *ALICE_VULN)
    # A form on an attacker's site would send exactly this, with no token.
    client.post("/note/new", data={"title": "planted-by-csrf", "content": "x"})
    assert "planted-by-csrf" in client.get("/").text


def test_v10_csrf_secure(secure):
    client = login(secure, *ALICE_SECURE)
    resp = client.post("/note/new", data={"title": "planted-by-csrf", "content": "x"})
    assert resp.status_code == 400
    assert "planted-by-csrf" not in client.get("/").text


# ------------------------------------------------ V-11 no brute-force protection
def test_v11_bruteforce_vulnerable(vuln):
    client = vuln.app.test_client()
    codes = [client.post("/login", data={"username": "alice", "password": f"guess{i}"}).status_code
             for i in range(20)]
    assert 429 not in codes
    assert "Shopping" in login(vuln, *ALICE_VULN).get("/").text   # never locked out


def test_v11_bruteforce_secure(secure):
    client = secure.app.test_client()
    codes = [post(client, "/login", {"username": "alice", "password": f"guess{i}"}, "/login").status_code
             for i in range(8)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429] * 3
    # even the right password is refused while the account is locked
    assert post(client, "/login", {"username": "alice", "password": "alice-demo-2026"},
                "/login").status_code == 429


# ------------------------------------------------ V-12 debug mode / error leaks
def test_v12_error_leak_vulnerable(vuln):
    vuln.app.config["PROPAGATE_EXCEPTIONS"] = False
    client = login(vuln, *ALICE_VULN)
    resp = client.post("/import", data={"backup": "bm90IGEgcGlja2xl"})
    assert resp.status_code == 500 and "invalid load key" in resp.text   # internals leaked
    assert "debug=True" in (ROOT / "vulnerable_app" / "app.py").read_text()


def test_v12_error_leak_secure(secure):
    secure.app.config["PROPAGATE_EXCEPTIONS"] = False

    @secure.app.route("/boom")
    def boom():
        raise RuntimeError("internal path C:\\secret\\db.sqlite")

    resp = secure.app.test_client().get("/boom")
    assert resp.status_code == 500 and "secret" not in resp.text
    assert "debug=True" not in (ROOT / "secure_app" / "app.py").read_text()


# ------------------------------------------------ hardening extras
def test_secure_headers(secure):
    resp = secure.app.test_client().get("/login")
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_secure_app_still_works(secure):
    client = login(secure, *ALICE_SECURE)
    post(client, "/note/new", {"title": "hello", "content": "world"})
    assert "hello" in client.get("/").text
    assert "PING" in client.get("/").text
    resp = client.get("/tools/ping", query_string={"host": "127.0.0.1"})
    assert resp.status_code == 200
