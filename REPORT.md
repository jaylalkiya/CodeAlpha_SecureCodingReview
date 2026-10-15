# Secure Coding Review: NoteVault

**CodeAlpha Cyber Security Internship, Task 3**
Reviewer: Jay Lalkiya · Date: 15 October 2026

| | |
|---|---|
| **Target** | NoteVault, a Python 3.12 / Flask 3.1 note-taking web app (`vulnerable_app/`) |
| **Scope** | All application code (`app.py`, 227 lines) and the Jinja2 templates |
| **Method** | Manual line-by-line review, static analysis with Bandit 1.9.4, and a proof-of-concept exploit for every finding (pytest) |
| **Result** | **12 vulnerabilities: 3 Critical, 6 High, 3 Medium.** All 12 are fixed in `secure_app/` and verified by 26 passing tests |

---

## 1. Executive summary

NoteVault lets users register, log in, write private notes, ping a host,
download shared files and back up their notes. The review found that an
unauthenticated attacker can **log in as the administrator without a
password** (SQL injection), and any logged-in user can **run commands on
the server** (command injection, insecure deserialization), **read every
user's notes** (IDOR) and **download the database and source code** (path
traversal).

The most dangerous issues all come from one root cause: **user input is
trusted**. It is pasted into SQL, into shell commands, into file paths, into
HTML and into `pickle`. The fixed build treats every input as untrusted data:
parameterised queries, argument lists without a shell, `send_from_directory`,
Jinja auto-escaping and JSON.

Automated scanning alone was not enough. Bandit flagged 6 of the 12 findings;
the other 6 (IDOR, XSS, path traversal, open redirect, CSRF, missing rate
limiting) are logic flaws that only manual review caught.

## 2. Methodology

1. **Manual review.** Read every route in `app.py` and every template,
   following each piece of request data (`request.form`, `request.args`,
   cookies) to the place it is used ("source to sink" tracing). Checked
   against the OWASP Top 10 (2021) and the OWASP ASVS checklist areas:
   authentication, session management, access control, input handling,
   cryptography, error handling and configuration.
2. **Static analysis.** Ran Bandit over both builds
   (`scan_results/bandit_*.txt`).
3. **Exploitation.** Wrote a harmless proof-of-concept for each finding in
   `tests/test_findings.py`. Every finding has one test showing the attack
   works on the vulnerable build and one showing it fails on the secure build.
4. **Remediation and retest.** Fixed each issue in `secure_app/app.py`,
   then re-ran the tests and Bandit.

**Severity scale:** *Critical* means remote code execution or full
authentication bypass. *High* means a serious data breach or account
takeover. *Medium* means it needs user interaction or makes other attacks
easier.

## 3. Findings summary

| ID | Vulnerability | Severity | CWE | OWASP 2021 | Location (vulnerable_app) | Bandit |
|---|---|---|---|---|---|---|
| V-02 | SQL injection in login | **Critical** | CWE-89 | A03 Injection | `app.py:95-97` | B608 |
| V-06 | OS command injection in ping tool | **Critical** | CWE-78 | A03 Injection | `app.py:178` | B602 |
| V-08 | Insecure deserialization (pickle) in import | **Critical** | CWE-502 | A08 Integrity Failures | `app.py:199` | B301 |
| V-01 | Hardcoded secret key and admin password | High | CWE-798 | A07 Auth Failures | `app.py:26-27` | B105 |
| V-03 | Unsalted MD5 password hashes, no password policy | High | CWE-916, CWE-521 | A02 Crypto Failures | `app.py:52, 109` | B324 |
| V-04 | Stored cross-site scripting (XSS) | High | CWE-79 | A03 Injection | `templates/note.html:5` | missed |
| V-05 | IDOR: read/delete any user's note | High | CWE-639 | A01 Broken Access Control | `app.py:141, 166` | missed |
| V-07 | Path traversal in file download | High | CWE-22 | A01 Broken Access Control | `app.py:189` | missed |
| V-12 | Debug mode on, error details leaked | High | CWE-489, CWE-209 | A05 Misconfiguration | `app.py:221, 227` | B201 |
| V-09 | Open redirect after login | Medium | CWE-601 | A01 Broken Access Control | `app.py:101` | missed |
| V-10 | No CSRF protection | Medium | CWE-352 | A01 Broken Access Control | `app.py:154, 166` | missed |
| V-11 | No brute-force protection on login | Medium | CWE-307 | A07 Auth Failures | `app.py:102` | missed |

## 4. Detailed findings

### V-02 SQL injection in login (Critical)

**Vulnerable code** (`vulnerable_app/app.py:95`)
```python
query = ("SELECT * FROM users WHERE username = '" + username +
         "' AND password = '" + hash_password(password) + "'")
user = get_db().execute(query).fetchone()
```
**Impact.** The username is concatenated into the SQL string. Entering
`admin' --` as the username turns the query into
`... WHERE username = 'admin' --' AND password = ...`. The `--` comments out
the password check, so the attacker is logged in as admin with any password.

**Proof:** `test_v02_sql_injection_vulnerable` logs in as admin and reads the
"Server root password" note.

**Fix** (`secure_app/app.py`, login): a parameterised query, where the
database driver sends input as data and never as SQL. The password is then
checked separately with a constant-time hash comparison.
```python
user = get_db().execute("SELECT * FROM users WHERE username = ?",
                        (username,)).fetchone()
if user and check_password_hash(user["password"], password):
```

### V-06 OS command injection in ping tool (Critical)

**Vulnerable code** (`vulnerable_app/app.py:178`)
```python
output = subprocess.run("ping -n 1 " + host, shell=True, ...).stdout
```
**Impact.** With `shell=True` the whole string goes to the system shell.
`127.0.0.1 & whoami` runs `whoami` (or any other command) with the web
server's privileges. That means full server compromise.

**Proof:** `test_v06_command_injection_vulnerable` injects
`& echo PWNED-4242` and finds the output in the page.

**Fix:** validate the host against a strict allow-list (a valid IP address or
DNS hostname), then call `ping` by absolute path with an argument list and
`shell=False`. With no shell, characters like `&`, `;` and `|` have no special
meaning.
```python
if not valid_host(host):
    return ..., 400
subprocess.run([ping_exe, count_flag, "1", host], shell=False, timeout=10)
```

### V-08 Insecure deserialization: pickle (Critical)

**Vulnerable code** (`vulnerable_app/app.py:199`)
```python
notes = pickle.loads(base64.b64decode(blob))
```
**Impact.** `pickle` can rebuild arbitrary Python objects, and an object's
`__reduce__` method can name any function to call during loading. An
attacker who pastes a crafted "backup" runs code on the server.

**Proof:** `test_v08_pickle_rce_vulnerable` sends a payload that creates a
marker file. The file appears, which proves code execution.

**Fix:** backups are now JSON, which can only hold plain data (lists,
strings, numbers). The structure is validated: at most 100 notes, each with a
string `title` and `content`, both length-limited.

### V-01 Hardcoded secret key and admin password (High)

**Vulnerable code** (`vulnerable_app/app.py:26`)
```python
app.secret_key = "notevault-dev-key-123"
ADMIN_PASSWORD = "admin123"
```
**Impact.** Flask signs the session cookie with `secret_key`. Anyone who
knows the key (from the repository, or through V-07) can **forge a session
cookie for any user ID** and become admin without logging in. The admin
password is also visible in the source and is easy to guess.

**Proof:** `test_v01_hardcoded_secret_vulnerable` signs `{"user_id": 1}`
with the leaked key and reads the admin's notes.

**Fix:** the key is read from the `NOTEVAULT_SECRET_KEY` environment variable,
falling back to a 256-bit random value from `secrets.token_hex(32)`. The admin
password comes from `NOTEVAULT_ADMIN_PASSWORD`, or is randomly generated
and printed once at setup. Session cookies are also `HttpOnly`,
`SameSite=Lax`, optionally `Secure`, and expire after 30 minutes.

### V-03 Weak password storage and no password policy (High)

**Vulnerable code** (`vulnerable_app/app.py:52`)
```python
return hashlib.md5(password.encode()).hexdigest()
```
**Impact.** MD5 is fast and unsalted. Leaked hashes (see V-07) can be cracked
with rainbow tables or a GPU at billions of guesses per second, and users
with the same password get the same hash. Registration also accepts
passwords like `1`.

**Proof:** `test_v03_weak_hashing_vulnerable` shows the stored 32-hex MD5
hash and a successful registration with the password `1`.

**Fix:** `werkzeug.security.generate_password_hash(method="scrypt")` gives a
salted, deliberately slow, memory-hard hash. Passwords must be at least 10
characters with letters and digits, and usernames are validated.

### V-04 Stored cross-site scripting (High)

**Vulnerable code** (`vulnerable_app/templates/note.html:5`)
```html
<div>{{ note.content|safe }}</div>
```
**Impact.** `|safe` switches off Jinja's auto-escaping, so a note containing
`<script>` runs in the browser of whoever views it. Combined with V-05, an
attacker can plant script that runs in the admin's session.

**Proof:** `test_v04_stored_xss_vulnerable` finds the raw `<script>` tag in
the page.

**Fix:** removed `|safe`, so content is HTML-escaped (`&lt;script&gt;`). As
defence in depth, the secure build also sends a Content-Security-Policy
(`script-src 'self'`) that blocks inline scripts even if escaping were ever
missed.

### V-05 Insecure direct object reference (High)

**Vulnerable code** (`vulnerable_app/app.py:141`)
```python
note = get_db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
```
**Impact.** The app checks that you are logged in, but not that the note is
yours. Alice can visit `/note/1` and read the admin's "Server root password",
or POST to `/note/1/delete` and delete it.

**Proof:** `test_v05_idor_vulnerable` reads and then deletes the admin's note
as Alice.

**Fix:** every lookup includes the owner:
`WHERE id = ? AND owner_id = ?`. Someone else's note returns **404, not
403**, so attackers cannot even confirm which IDs exist.

### V-07 Path traversal in file download (High)

**Vulnerable code** (`vulnerable_app/app.py:189`)
```python
return send_file(os.path.join(FILES_DIR, name))
```
**Impact.** `?file=../notevault.db` walks out of the `files` folder and
downloads the whole database, including password hashes. `?file=../app.py`
downloads the source code with the secret key. An absolute path also works,
because `os.path.join` throws away the folder prefix.

**Proof:** `test_v07_path_traversal_vulnerable` downloads `app.py` and the
SQLite database.

**Fix:** `send_from_directory(FILES_DIR, name)` uses Werkzeug's `safe_join`,
which refuses any path that resolves outside the folder and returns 404.

### V-12 Debug mode and verbose errors (High)

**Vulnerable code** (`vulnerable_app/app.py:221, 227`)
```python
return "<h1>Server error</h1><pre>" + str(e.original_exception) + "</pre>", 500
app.run(host="127.0.0.1", port=5000, debug=True)
```
**Impact.** With `debug=True`, Werkzeug's interactive debugger lets anyone
who triggers an error run Python code in the browser if the app is ever
exposed beyond localhost. The custom error page also shows internal exception
messages, which helps attackers map the system.

**Proof:** `test_v12_error_leak_vulnerable` triggers an error and sees the
internal `pickle` exception text.

**Fix:** debug is off unless `NOTEVAULT_DEBUG=1`. Errors are logged on the
server with `log.exception`, and the user sees a generic message.

### V-09 Open redirect (Medium)

**Vulnerable code** (`vulnerable_app/app.py:101`)
```python
return redirect(request.args.get("next") or url_for("index"))
```
**Impact.** A phishing link like
`/login?next=https://evil.example/phish` shows the real NoteVault login, then
sends the user to the attacker's lookalike site, which can ask them to "log
in again".

**Fix:** `safe_next()` only allows same-site relative paths. It rejects
absolute URLs, `//host` and backslash tricks such as `/\evil.example`.

### V-10 Cross-site request forgery (Medium)

**Impact.** State-changing POST requests (new note, delete note, import) have
no token. A page on another site can submit a hidden form, and the victim's
browser sends their session cookie with it.

**Proof:** `test_v10_csrf_vulnerable` creates a note with a token-less POST.

**Fix:** a per-session random CSRF token (`secrets.token_urlsafe(32)`) goes
into every form and is checked on every POST with the constant-time
`hmac.compare_digest`. A missing or wrong token returns 400. The
`SameSite=Lax` cookie adds a second layer.

### V-11 No brute-force protection (Medium)

**Impact.** Unlimited login attempts allow password guessing and credential
stuffing. Combined with V-03 (no policy), weak passwords fall quickly.

**Proof:** `test_v11_bruteforce_vulnerable` makes 20 failed attempts with no
lockout.

**Fix:** after 5 failed attempts within 5 minutes for the same client and
username, the login returns HTTP 429. During the lockout even the correct
password is refused, so an attacker cannot tell when they have guessed it.
The session is also reset on successful login, which prevents session
fixation.

## 5. Attack chain

The findings make each other worse. A realistic chain, starting from a
normal low-privilege account:

1. **V-07**: download `../app.py` and read the hardcoded secret key (**V-01**).
2. **V-01**: forge a session cookie with `user_id = 1`. You are now admin.
3. **V-05**: read every note on the system.
4. **V-08** or **V-06**: run commands on the server.

Step 1 alone also gives the full database with MD5 hashes (**V-03**). Each
fix breaks this chain on its own, which is the point of defence in depth.

## 6. Verification

**Exploit tests**: `python -m pytest -v` gives **26 passed**
(`scan_results/pytest_results.txt`): 12 attacks confirmed on the vulnerable
build, the same 12 blocked on the secure build, plus security header and
"app still works" checks.

**Static analysis (Bandit 1.9.4)**

| Build | High | Medium | Low | Total |
|---|---|---|---|---|
| vulnerable_app | 3 | 2 | 4 | 9 |
| secure_app | 0 | 0 | 0 | **0** |

Bandit's 3 remaining hits on the secure build were reviewed and marked with
`# nosec`, each with the reason written in a comment:
- **B404** (`import subprocess`): needed for ping; it is only ever called
  with a fixed argument list.
- **B603** (subprocess call): `shell=False`, absolute executable path, and
  the host is allow-list validated first.
- **B704** (`Markup`): it wraps a server-generated token that is escaped
  first, so no user input reaches it.

## 7. Further recommendations

These go beyond the scope of the fixes but would be next steps for a
production deployment:

1. Use maintained libraries: **Flask-WTF** for CSRF and **Flask-Limiter**
   with Redis for rate limiting. The in-memory limiter here resets on
   restart and does not share state across worker processes.
2. Serve only over **HTTPS** and set `NOTEVAULT_HTTPS=1` so the session
   cookie gets the `Secure` flag. Add HSTS.
3. Change `/logout` to a POST with a CSRF token, so another site cannot
   log a user out.
4. Run **pip-audit** in CI to catch vulnerable dependencies, and Bandit on
   every commit.
5. Run the app as a low-privilege user under a production WSGI server
   (gunicorn/waitress), never with `app.run()`.
6. Add audit logging for logins, failed logins and deletions.

## 8. References

- OWASP Top 10 (2021): https://owasp.org/Top10/
- OWASP Cheat Sheet Series: SQL Injection Prevention, OS Command Injection
  Defense, Deserialization, Password Storage, CSRF Prevention
- MITRE CWE: https://cwe.mitre.org/
- Bandit documentation: https://bandit.readthedocs.io/
- Flask security considerations: https://flask.palletsprojects.com/en/stable/web-security/
