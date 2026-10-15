# CodeAlpha_SecureCodingReview

**CodeAlpha Cyber Security Internship, Task 3: Secure Coding Review**

A security audit of **NoteVault**, a small Python/Flask note-taking web app.
I reviewed the code by hand, scanned it with Bandit, proved each
vulnerability with a working exploit test, then wrote a fixed version and
proved every attack is blocked.

> **Full report: [REPORT.md](REPORT.md)**

## Results

| | Vulnerable build | Secure build |
|---|---|---|
| Vulnerabilities found | **12** (3 Critical, 6 High, 3 Medium) | **0** |
| Exploit tests | 12 / 12 attacks succeed | 12 / 12 attacks blocked |
| Bandit static scan | 9 issues (3 High) | 0 issues |

| ID | Vulnerability | Severity | Fix |
|---|---|---|---|
| V-02 | SQL injection (login bypass) | Critical | Parameterised queries |
| V-06 | OS command injection | Critical | Allow-list + argv, no shell |
| V-08 | Insecure deserialization (pickle) | Critical | JSON + schema validation |
| V-01 | Hardcoded secret key and password | High | Environment variables / random secrets |
| V-03 | MD5 password hashing, no policy | High | scrypt + password policy |
| V-04 | Stored XSS | High | Auto-escaping + CSP |
| V-05 | IDOR (read/delete others' notes) | High | Owner check on every query |
| V-07 | Path traversal | High | `send_from_directory` |
| V-12 | Debug mode, error leakage | High | Debug off, generic errors |
| V-09 | Open redirect | Medium | Same-site path check |
| V-10 | CSRF | Medium | Per-session CSRF token |
| V-11 | No brute-force protection | Medium | Login lockout (HTTP 429) |

## Project structure

```
vulnerable_app/   NoteVault with the 12 flaws; each is tagged # [V-XX]
secure_app/       Fixed NoteVault; each fix is tagged # [FIX V-XX]
tests/            test_findings.py: an exploit proof for every finding
scan_results/     Bandit reports (txt + json) and pytest output
REPORT.md         Full findings report: impact, proof, fix, CWE/OWASP mapping
```

## Run it yourself

```bash
pip install -r requirements.txt

# exploit tests: every attack works on one build, fails on the other
python -m pytest -v

# static analysis
python -m bandit -r vulnerable_app
python -m bandit -r secure_app

# try the apps in a browser (localhost only)
python vulnerable_app/app.py      # http://127.0.0.1:5000  (alice / alice2026)
python secure_app/app.py          # http://127.0.0.1:5001  (alice / alice-demo-2026)
```

Things to try on the vulnerable build: log in with username `admin' --`,
open `/note/1` as alice, ping `127.0.0.1 & whoami`, or download
`/download?file=../app.py`. Then try the same on the secure build.

> ⚠️ `vulnerable_app` is deliberately insecure. Run it only on localhost for
> learning. Never deploy it.

## Tools

Python 3.12 · Flask 3.1 · Bandit 1.9.4 · pytest · OWASP Top 10 (2021) · MITRE CWE
