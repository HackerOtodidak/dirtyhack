# Vulnerable Test Application

Lightweight Flask app intentionally seeded with authz and access-control weaknesses for exercising SecureVibes DAST skills.

## Quickstart
1) Python 3.9+ recommended  
2) Install deps (keep the venv outside Git):
```bash
cd test_vulnerable_app
python -m venv .venv
source .venv/bin/activate  # .venv\Scripts\activate on Windows
pip install -r requirements.txt
```
3) Run the app:
```bash
python app.py
```
The server listens on `http://0.0.0.0:5001`.

## Test Accounts
- `alice` / `alice123` (user)
- `bob` / `bob456` (user)
- `admin` / `admin789` (admin)
- Legacy cookies (optional): `session=alice_session`, `session=bob_session`, `session=admin_session`

## Known Vulnerabilities (for scanning)
- IDOR, vertical/horizontal escalation, missing auth, forced browsing
- Mass assignment, CSRF, CORS reflection, referer bypass, 403 bypass tricks
- Directory listing, backup file exposure, hardcoded credentials

## Running SecureVibes DAST Against It
From repo root (not inside the test app):
```bash
securevibes scan test_vulnerable_app \
  --dast \
  --target-url http://localhost:5001 \
  --dast-accounts test_vulnerable_app/test_accounts.json \
  --debug --force
```
Artifacts (`.securevibes/`, `.claude/`, `venv/`) are ignored via `.gitignore`.
